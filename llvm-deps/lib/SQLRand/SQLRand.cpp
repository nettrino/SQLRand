/*
 * Copyright (c) 2014, Columbia University
 * All rights reserved.
 *
 * This software was developed by Theofilos Petsios <theofilos@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in September 2014.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Columbia University nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <boost/algorithm/string.hpp>
#include <cctype>
#include <fstream>
#include <sstream>
#include <string>
#include <iostream>
#include <iterator>
#include <vector>

#include "llvm/Instruction.h"
#include "llvm/Instructions.h"
#include "llvm/LLVMContext.h"
#include "llvm/Function.h"
#include "llvm/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include "llvm/IRBuilder.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"

#include "Infoflow.h"
#include "Slice.h"

#include "SQLRand.h"

using std::set;
using namespace llvm;
using namespace deps;

namespace {
//FIXME need to handle constant assignments as well!
//What about environment variables?
static const struct CallTaintEntry bLstSourceSummaries[] = {
  //FIXME check which args need to be tainted. For now we are tainting
  //the variable part to see if it leads to a mysql query
  // function  tainted values   tainted direct memory tainted root ptrs
  { "strcpy",  TAINTS_NOTHING,  	TAINTS_ARG_1,    TAINTS_NOTHING },
  { "strncpy", TAINTS_NOTHING,  	TAINTS_ARG_1,    TAINTS_NOTHING },
  { "strcat",  TAINTS_NOTHING,  	TAINTS_ARG_1,    TAINTS_NOTHING },
  { "strncat", TAINTS_NOTHING,  	TAINTS_ARG_1,    TAINTS_NOTHING },
  { "sprintf", TAINTS_NOTHING,  	TAINTS_ARG_1,    TAINTS_NOTHING },
  { "snprintf",TAINTS_NOTHING,  	TAINTS_ARG_1,    TAINTS_NOTHING },
  { "memcpy",  TAINTS_NOTHING,  	TAINTS_ARG_1,    TAINTS_NOTHING },
  { "memmove", TAINTS_NOTHING,  	TAINTS_ARG_1,    TAINTS_NOTHING },
  { "getenv",  TAINTS_RETURN_VAL, TAINTS_ARG_1,    TAINTS_NOTHING },
  { 0,         TAINTS_NOTHING,  TAINTS_NOTHING, 	 TAINTS_NOTHING }
};

static const struct CallTaintEntry sanitizeSummaries[] = {
  // function,  	tainted values,   tainted direct memory, tainted root ptrs
  { "mysql_real_query", TAINTS_ARG_2,  	TAINTS_NOTHING,    	TAINTS_NOTHING },
  { "mysql_query", 	  TAINTS_ARG_2,  	TAINTS_NOTHING,    	TAINTS_NOTHING },
  { "PQexec", 		  TAINTS_ARG_2,  	TAINTS_NOTHING,    	TAINTS_NOTHING },
  { 0,          		TAINTS_NOTHING,		TAINTS_NOTHING,		TAINTS_NOTHING }
};


/* ****************************************************************************
 * ============================================================================
 *  						Taint Functions
 * ============================================================================
 * ****************************************************************************/
static const CallTaintEntry *
findEntryForFunction(const CallTaintEntry *Summaries,
                     const std::string &FuncName) {
  unsigned Index;

  for (Index = 0; Summaries[Index].Name; ++Index) {
    if (Summaries[Index].Name == FuncName)
      return &Summaries[Index];
  }

  // Return the default summary.
  return &Summaries[Index];
}

void
SQLRandPass::taintForward(std::string srcKind,
                          CallInst *ci,
                          const CallTaintEntry *entry)
{
  const CallTaintSummary *vSum = &(entry->ValueSummary);
  const CallTaintSummary *dSum = &(entry->DirectPointerSummary);
  const CallTaintSummary *rSum = &(entry->RootPointerSummary);

  /* vsum */
  if (vSum->TaintsReturnValue)
    infoflow->setTainted(srcKind, *ci);

  for (unsigned ArgIndex = 0; ArgIndex < vSum->NumArguments; ++ArgIndex) {
    if (vSum->TaintsArgument[ArgIndex])
      infoflow->setTainted(srcKind, *(ci->getOperand(ArgIndex)));
  }

  /* dsum */
  if (dSum->TaintsReturnValue)
    infoflow->setDirectPtrTainted(srcKind, *ci);

  for (unsigned ArgIndex = 0; ArgIndex < dSum->NumArguments; ++ArgIndex) {
    if (dSum->TaintsArgument[ArgIndex])
      infoflow->setDirectPtrTainted(srcKind, *(ci->getOperand(ArgIndex)));
  }

  /* rsum */
  if (rSum->TaintsReturnValue)
    infoflow->setReachPtrTainted(srcKind, *ci);

  for (unsigned ArgIndex = 0; ArgIndex < rSum->NumArguments; ++ArgIndex) {
    if (rSum->TaintsArgument[ArgIndex])
      infoflow->setReachPtrTainted(srcKind, *(ci->getOperand(ArgIndex)));
  }
}

void
SQLRandPass::taintBackwards(std::string sinkKind,
                            CallInst *ci,
                            const CallTaintEntry *entry)
{
  const CallTaintSummary *vSum = &(entry->ValueSummary);
  const CallTaintSummary *dSum = &(entry->DirectPointerSummary);
  const CallTaintSummary *rSum = &(entry->RootPointerSummary);

  /* vsum */
  if (vSum->TaintsReturnValue)
    infoflow->setUntainted(sinkKind, *ci);

  for (unsigned ArgIndex = 0; ArgIndex < vSum->NumArguments; ++ArgIndex) {
    if (vSum->TaintsArgument[ArgIndex])
      infoflow->setUntainted(sinkKind, *(ci->getOperand(ArgIndex)));
  }

  /* dsum */
  if (dSum->TaintsReturnValue)
    infoflow->setDirectPtrUntainted(sinkKind, *ci);

  for (unsigned ArgIndex = 0; ArgIndex < dSum->NumArguments; ++ArgIndex) {
    if (dSum->TaintsArgument[ArgIndex])
      infoflow->setDirectPtrUntainted(sinkKind,
                                      *(ci->getOperand(ArgIndex)));
  }

  /* rsum */
  if (rSum->TaintsReturnValue)
    infoflow->setReachPtrUntainted(sinkKind, *ci);

  for (unsigned ArgIndex = 0; ArgIndex < rSum->NumArguments; ++ArgIndex) {
    if (rSum->TaintsArgument[ArgIndex])
      infoflow->setReachPtrUntainted(sinkKind,
                                     *(ci->getOperand(ArgIndex)));
  }
}

bool
SQLRandPass::checkBackwardTainted(Value &V, InfoflowSolution* soln, bool direct)
{
  bool ret = (!soln->isTainted(V));

  if (direct)
    ret = ret || (!soln->isDirectPtrTainted(V));

  return ret;
}

bool
SQLRandPass::checkForwardTainted(Value &V, InfoflowSolution* soln, bool direct)
{
  bool ret = (soln->isTainted(V));

  if (direct)
    ret = ret || (soln->isDirectPtrTainted(V));

  return ret;
}

/* ****************************************************************************
 * ============================================================================
 *  						Solution Functions
 * ============================================================================
 * ****************************************************************************/

InfoflowSolution *
SQLRandPass::getForwardSolFromEntry(std::string srcKind,
                                    CallInst *ci,
                                    const CallTaintEntry *entry)
{

  //XXX Do not change order
  taintForward(srcKind, ci, entry);

  std::set<std::string> kinds;
  kinds.insert(srcKind);

  //This does forward analysis
  InfoflowSolution *fsoln = infoflow->leastSolution(kinds, false, true);

  return fsoln;
}

InfoflowSolution *
SQLRandPass::getBackwardsSol(std::string sinkKind, CallInst *ci)
{

  //XXX Do not change order
  infoflow->setUntainted(sinkKind, *ci);

  std::set<std::string> kinds;
  kinds.insert(sinkKind);

  InfoflowSolution *fsoln = infoflow->greatestSolution(kinds, false);

  return fsoln;
}

InfoflowSolution *
SQLRandPass::getBackwardsSolFromEntry(std::string sinkKind,
                                      CallInst *ci,
                                      const CallTaintEntry *entry)
{

  //XXX Do not change order
  taintBackwards(sinkKind, ci, entry);

  std::set<std::string> kinds;
  kinds.insert(sinkKind);

  InfoflowSolution *fsoln = infoflow->greatestSolution(kinds, false);

  return fsoln;
}

InfoflowSolution *
SQLRandPass::getForwardSolFromGlobal(std::string srcKind, Value *val)
{
  infoflow->setTainted(srcKind, *val);

  std::set<std::string> kinds;
  kinds.insert(srcKind);
  InfoflowSolution *fsoln = infoflow->leastSolution(kinds, false, true);

  return fsoln;
}

/* ****************************************************************************
 * ============================================================================
 *  							Main Pass
 * ============================================================================
 * ****************************************************************************/

int
SQLRandPass::doInitialization(Module &M)
{
  infoflow = &getAnalysis<Infoflow>();
  dbg("Initialization");

  int sqlType = getSQLType(M);

  if (sqlType == 0) {
    /* MySQL */
    dbg("Found db: MySQL");
    hashSQLKeywords(true);
  } else if (sqlType == 1) {
    /* PGSQL */
    dbg("Found db: PostgreSQL");
    hashSQLKeywords(false);
  } else {
    /* abort */
    return -1;
  }
  unique_id = 0;

  for (Module::global_iterator ii = M.global_begin();
       ii != M.global_end();
       ++ii){
    GlobalVariable *gv = ii;
    if (gv->isConstant()) {
      std::string name = gv->getName().str();
      for (GlobalVariable::use_iterator U = gv->use_begin();
           U != gv->use_end();
           U++ ) {
        User *user = dyn_cast<User>(*U);
        Value *val = user->getOperand(0);
        if (isa<ConstantExpr>(user) && (val != NULL)) {
          InfoflowSolution *fsoln =
              getForwardSolFromGlobal(name, val);
          if (backwardsFromGlobal(M, fsoln, val) &&
              gv->hasInitializer()) {
            dbg("FOUND mysql from global Variable");
            ConstantDataSequential *cds =
                dyn_cast<ConstantDataSequential>(gv->getInitializer());
            std::string sanitized =
                sanitizeString(cds->getAsString().str());
            Constant *san =
                ConstantDataArray::getString(M.getContext(),
                                             sanitized, false);
            if (san->getType() == gv->getInitializer()->getType()) {
              gv->setInitializer(san);
            }
          }
        }
      }
    }
  }

  return 0;
}


void
SQLRandPass::sanitizeLiteralsBackwards(Module &M, InfoflowSolution *sol)
{
  for (Module::iterator mi = M.begin(); mi != M.end(); mi++) {
    Function& F = *mi;
    for (Function::iterator bi = F.begin(); bi != F.end(); bi++) {
      BasicBlock& B = *bi;
      for (BasicBlock::iterator ii = B.begin(); ii !=B.end(); ii++) {
        if (CallInst* ci = dyn_cast<CallInst>(ii)) {
          Function* f = ci->getCalledFunction();
          if (!f)
            continue;

          for (size_t i = 0; i < ci->getNumArgOperands(); i++) {
            if (isLiteral(ci->getArgOperand(i)) &&
                checkBackwardTainted(*(ci->getArgOperand(i)),sol)) {
              Value *s = sanitizeArgOp(M,
                                       ci->getArgOperand(i));

              ci->setArgOperand(i, s);
            }
          }
        }
      }
    }
  }
}
void
SQLRandPass::doFinalization(Module &M)
{
  dbg("Removing checks");
  for (Module::iterator mi = M.begin(); mi != M.end(); mi++) {
    Function& F = *mi;
    for (Function::iterator bi = F.begin(); bi != F.end(); bi++) {
      BasicBlock& B = *bi;
      for (BasicBlock::iterator ii = B.begin(); ii !=B.end(); ii++) {
        if (CallInst* ci = dyn_cast<CallInst>(ii)) {
          Function* f = ci->getCalledFunction();
          if (!f)
            continue;

          const CallTaintEntry *entry =
              findEntryForFunction(sanitizeSummaries, f->getName());
          if (entry->Name) {
            /* Update the arg if it is a ConstExpr */
            if (isLiteral(ci->getArgOperand(1))) {
              Value *s = sanitizeArgOp(M,
                                       ci->getArgOperand(1));

              ci->setArgOperand(1, s);
            } else {
              std::string sinkKind = getKindId("sql", &unique_id);
              InfoflowSolution *soln = getBackwardsSol(sinkKind,
                                                       ci);

              sanitizeLiteralsBackwards(M, soln);
            }
            /* Construct Function */
            insertSQLCheckFunction(M,
                                   "__sqlrand_" + f->getName().str(),
                                   ci,
                                   ii);
            ii = B.begin();
          }
        }
      }
    }
  }
}

Value *
SQLRandPass::sanitizeArgOp(Module &M, Value *op)
{
  ConstantExpr *constExpr = dyn_cast<ConstantExpr>(op);
  GlobalVariable *gv = dyn_cast<GlobalVariable>(constExpr->getOperand(0));

  if (gv == NULL || !gv->hasInitializer())
    return op;

  std::string var_name = gv->getName().str();
  ConstantDataSequential *cds =
      dyn_cast<ConstantDataSequential>(gv->getInitializer());

  if (cds != NULL && cds->isString()) {
    std::string sanitized = sanitizeString(cds->getAsString().str());
    Constant *san =
        ConstantDataArray::getString(M.getContext(), sanitized, false);

    if (san->getType() == gv->getInitializer()->getType()) {
      dbgMsg(cds->getAsString().str() + " becomes :", sanitized);
      gv->setInitializer(san);
    } else {
      san->getType()->dump();
      errs() << "\t";
      gv->getInitializer()->dump();
      errs() << "\n";
    }
  }
  constExpr->setOperand(0, gv);
  return dyn_cast<Value>(constExpr);
}


bool
SQLRandPass::runOnModule(Module &M)
{
  int ret = doInitialization(M);
  /* If we did not find SQL abort */
  if (ret == -1)
    return false;

  for (Module::iterator mi = M.begin(); mi != M.end(); mi++) {
    Function& F = *mi;
    for (Function::iterator bi = F.begin(); bi != F.end(); bi++) {
      BasicBlock& B = *bi;
      for (BasicBlock::iterator ii = B.begin(); ii !=B.end(); ii++) {
        if (CallInst* ci = dyn_cast<CallInst>(ii)) {
          Function* f = ci->getCalledFunction();
          if (!f)
            continue;

          /* Check if function needs to be sanitized */
          const CallTaintEntry *entry =
              findEntryForFunction(bLstSourceSummaries, f->getName());
          if (entry->Name) {
            std::string srcKind = getKindId("src", &unique_id);
            InfoflowSolution *fsoln =
                getForwardSolFromEntry(srcKind, ci, entry);

            if (backwardSlicingBlacklisting(M, fsoln, ci)) {
              if (f->getName() != "getenv") {
                /* If we found mysql sanitize */
                for (size_t i = 0;
                     i < ci->getNumArgOperands();
                     i++) {

                  if (isLiteral(ci->getArgOperand(i))) {
                    Value *s = sanitizeArgOp(M,
                                             ci->getArgOperand(i));

                    ci->setArgOperand(i, s);
                  }
                }
              } else {
                dbg("getenv called");
                if (isLiteral(ci)) {
                  dbg("Literal");
                  //Value *s = sanitizeArgOp(M, ci);
                  //ci = s;
                }
              }
            }
          }
        }
      }
    }
  }

  doFinalization(M);
  return false;
}

bool
SQLRandPass::backwardSlicingBlacklisting(Module &M,
                                         InfoflowSolution* fsoln,
                                         CallInst* srcCI)
{
  for (Module::iterator mi = M.begin(); mi != M.end(); mi++) {
    Function& F = *mi;
    for (Function::iterator bi = F.begin(); bi != F.end(); bi++) {
      BasicBlock& B = *bi;
      for (BasicBlock::iterator ii = B.begin(); ii !=B.end(); ii++) {
        if (CallInst* ci = dyn_cast<CallInst>(ii)) {
          Function *f = ci->getCalledFunction();
          if (!f)
            continue;

          const CallTaintEntry *entry =
              findEntryForFunction(sanitizeSummaries, f->getName());
          if (entry->Name) {
            if (checkForwardTainted(*(ci->getOperand(1)), fsoln)) {

              //this returns all sources that are tainted
              std::string sinkKind = getKindId("sql", &unique_id);

              InfoflowSolution *soln = getBackwardsSol(sinkKind,
                                                       ci);

              //check if source is in our list
              if (checkBackwardTainted(*srcCI, soln))
                return true;
            }
          }
        }
      }
    }
  }
  return false;
}

bool
SQLRandPass::backwardsFromGlobal(Module &M,
                                 InfoflowSolution* fsoln,
                                 Value* val)
{
  for (Module::iterator mi = M.begin(); mi != M.end(); mi++) {
    Function& F = *mi;
    for (Function::iterator bi = F.begin(); bi != F.end(); bi++) {
      BasicBlock& B = *bi;
      for (BasicBlock::iterator ii = B.begin(); ii !=B.end(); ii++) {
        if (CallInst* ci = dyn_cast<CallInst>(ii)) {
          Function *f = ci->getCalledFunction();
          if (!f)
            continue;

          const CallTaintEntry *entry =
              findEntryForFunction(sanitizeSummaries, f->getName());
          if (entry->Name) {
            if (checkForwardTainted(*(ci->getOperand(1)), fsoln)) {
              dbg("Found call from global (!)");
              return true;
            }
          }
        }
      }
    }
  }
  return false;
}

/* ****************************************************************************
 * ============================================================================
 *  							HELPER FUNCTIONS
 * ============================================================================
 * ****************************************************************************/

void
SQLRandPass::insertSQLCheckFunction(Module &M,
                                    std::string name,
                                    CallInst *ci,
                                    BasicBlock::iterator ii)
{
  Constant *fc = NULL;
  /* Create Args */
  std::vector<Value *> fargs;

  if (name == "__sqlrand_mysql_real_query") {
    fc = M.getOrInsertFunction(name,
                               /* type */	 ci->getType(),
                               /* arg0 */ 	 ci->getArgOperand(0)->getType(),
                               /* arg1 */ 	 ci->getArgOperand(1)->getType(),
                               /* arg2 */ 	 ci->getArgOperand(2)->getType(),
                               /* Linkage */ GlobalValue::ExternalLinkage,
                               (Type *)0);

    /* Push argument to Args */
    fargs.push_back(ci->getArgOperand(0));
    fargs.push_back(ci->getArgOperand(1));
    fargs.push_back(ci->getArgOperand(2));

  } else if ((name == "__sqlrand_mysql_query") ||
             (name == "__sqlrand_PQexec")) {
    fc = M.getOrInsertFunction(name,
                               /* type */	 ci->getType(),
                               /* arg0 */ 	 ci->getArgOperand(0)->getType(),
                               /* arg1 */ 	 ci->getArgOperand(1)->getType(),
                               /* Linkage */ GlobalValue::ExternalLinkage,
                               (Type *)0);

    /* Push argument to Args */
    fargs.push_back(ci->getArgOperand(0));
    fargs.push_back(ci->getArgOperand(1));
  }

  ArrayRef<Value *> functionArguments(fargs);
  CallInst *sqlCheck = CallInst::Create(fc, functionArguments, "");
  sqlCheck->setCallingConv(ci->getCallingConv());
  sqlCheck->setTailCall(ci->isTailCall());
  sqlCheck->setAttributes(ci->getAttributes());

  ReplaceInstWithInst(ci, sqlCheck);
}


int
SQLRandPass::getSQLType(Module &M)
{
  for (Module::iterator mi = M.begin(); mi != M.end(); mi++) {
    Function& F = *mi;
    for (Function::iterator bi = F.begin(); bi != F.end(); bi++) {
      BasicBlock& B = *bi;
      for (BasicBlock::iterator ii = B.begin(); ii !=B.end(); ii++) {
        if (CallInst* ci = dyn_cast<CallInst>(ii)) {
          Function* f = ci->getCalledFunction();
          if (!f)
            continue;
          if (StringRef(f->getName()).startswith("mysql_"))
            return 0;
          if (f->getName() == "PQexec")
            return 1;
        }
      }
    }
  }

  return -1;
}

/*
 * Checks if @word is one of MySQL reserved keywords
 */
bool
SQLRandPass::isKeyword(std::string word)
{
  /* convert to uppercase first so as not to miss smth */
  std::string up_word = boost::to_upper_copy(word);
  return MYSQL_KEYWORDS.find(word) != MYSQL_KEYWORDS.end();
}

/*
 * For now just add a padding
 */
std::string
SQLRandPass::pad(std::string word, std::string suffix)
{
  return word + "_" + suffix;
}

// trim from start
std::string &
SQLRandPass::ltrim(std::string &s) {
  s.erase(s.begin(),
          std::find_if(s.begin(),
                       s.end(),
                       std::not1(std::ptr_fun<int, int>(std::isspace))
                      )
         );
  return s;
}

// trim from end
std::string &
SQLRandPass::rtrim(std::string &s) {
  s.erase(std::find_if(s.rbegin(),
                       s.rend(),
                       std::not1(std::ptr_fun<int, int>(std::isspace))
                      ).base(),
          s.end());
  return s;
}

/*
 * Sanitize all possible keywords in the string. Leave the rest intact
 */
std::string
SQLRandPass::sanitizeString(std::string input)
{
  std::string word, sanitized, sanitizedWord;
  sanitized = "";
  size_t i = 0;
  while (i < input.length()) {
    if (isalnum(input[i])) {
      word = "";
      while (isalnum(input[i]) || input[i] == '_') {
        word += input[i];
        i++;
      }

      std::string up_word = boost::to_upper_copy(word);
      if (isKeyword(up_word)) {
        /* convert to uppercase first so as not to miss smth */
        sanitizedWord = keyToHash[up_word];
        sanitized += sanitizedWord;
      } else {
        sanitized += word;
      }
    }
    sanitized += input[i++];
  }
  return sanitized;
}

//FIXME
bool
SQLRandPass::isLiteral(Value *operand)
{
  return (isa<ConstantExpr>(operand));
}

//FIXME
bool
SQLRandPass::isVariable(Value *operand)
{
  return (isa<Instruction>(operand));
}


void
SQLRandPass::hashSQLKeywords(bool isMySQL)
{
  std::string hash, key;
  std::ofstream outfile;
  std::ifstream infile;

  if (isMySQL)
    infile.open(MYSQL_MAPPING_FILE, std::ios::binary | std::ios::in);
  else
    infile.open(PGSQL_MAPPING_FILE, std::ios::binary | std::ios::in);

  if (infile.is_open()) {
    std::string line;
    while (std::getline(infile, line)) {
      std::istringstream iss(line);
      iss >> hash;
      iss >> key;
      hashToKey[hash] = key;
      keyToHash[key] = hash;
    }
    infile.close();
    return;
  }

  /* If file not here, create it  */
  if (isMySQL)
    outfile.open(MYSQL_MAPPING_FILE, std::ios::binary);
  else
    outfile.open(PGSQL_MAPPING_FILE, std::ios::binary);

  if (outfile.is_open()) {
    for (std::set<std::string>::iterator it=MYSQL_KEYWORDS.begin();
         it!=MYSQL_KEYWORDS.end();
         ++it) {
      do {
        /* get a new hash until all hashes are unique */
        hash = hashString(*it);
      } while (hashToKey.count(hash) != 0);

      hashToKey[hash] = *it;
      keyToHash[*it] = hash;

      /* write to file */
      outfile << hash << " " << *it << "\n";
    }

    outfile.close();
  } else {
    dbg("Could not open mapping file");
    exit(-1);
  }
}

/*
 * Get hashed string of @input with the same length
 */
std::string
SQLRandPass::hashString(std::string input)
{
  char s[MAX_CHAR];
  unsigned int len = input.size();

  /* FIXME This is not random!! */
  static const char alphanum[] =
      "0123456789"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz";

  for (unsigned int i = 0; i < len; ++i) {
    s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
  }

  s[len] = 0;
  return std::string(s).substr(0, len);
}

/*
 * Randomizes suffix as string from /dev/urandom
 */
void
SQLRandPass::randomizeSuffix()
{
  char suffix[SUFFIX_LEN];
  FILE *fp;

  fp = fopen("/dev/urandom", "r");
  if (fp == NULL)
    exit(-1);

  if (fread(&suffix, sizeof(char), SUFFIX_LEN, fp) != SUFFIX_LEN)
    if (ferror(fp))
      exit(-1);
  fclose(fp);

  strncpy(SUFFIX, suffix, SUFFIX_LEN);
}

std::string
SQLRandPass::getKindId(std::string name, uint64_t *unique_id)
{
  std::stringstream SS;
  SS << (*unique_id)++;
  return name + SS.str();
}

void
SQLRandPass::dbgMsg(std::string a, std::string b)
{
  llvm::errs() << "\n[SQLRand] DBG:" << a << b << "\n";
}

void
SQLRandPass::dbg(std::string s)
{
  llvm::errs() << "\n[SQLRand] DBG:" << s << "\n";
}

} /* ------------------  namespace end ------------------ */


/* ****************************************************************************
 * ============================================================================
 *  				REGISTER PASS TO LLVM
 * ============================================================================
 * ****************************************************************************/

namespace  {

/* ID for SQLRandPass */
  char SQLRandPass::ID = 1;

  static RegisterPass<SQLRandPass>
      XX ("SQLRand", "Implements SQLRand Pass", true, true);

  static void
      initializeSQLRandPasses(PassRegistry &Registry) {
        llvm::initializeAllocIdentifyPass(Registry);
        llvm::initializePDTCachePass(Registry);
      }

  static void
      registerSQLRandPasses(const PassManagerBuilder &, PassManagerBase &PM)
      {
        PM.add(llvm::createPromoteMemoryToRegisterPass());
        PM.add(llvm::createPDTCachePass());
        PM.add(new SQLRandPass());
      }

  class StaticInitializer {
   public:
    StaticInitializer() {
      char* passend = getenv("__PASSEND__");

      if (passend) {
        errs() << "== EP_LoopOptimizerEnd ==\n";
        RegisterStandardPasses
            RegisterSQLRandPass(PassManagerBuilder::EP_LoopOptimizerEnd,
                                registerSQLRandPasses);
      } else {
        errs() << "== EP_ModuleOptimizerEarly ==\n";
        RegisterStandardPasses
            RegisterSQLRandPass(PassManagerBuilder::EP_ModuleOptimizerEarly,
                                registerSQLRandPasses);
      }

      PassRegistry &Registry = *PassRegistry::getPassRegistry();
      initializeSQLRandPasses(Registry);
    }
  };

  static StaticInitializer InitializeEverything;

} /* ------------------  namespace end ------------------ */
