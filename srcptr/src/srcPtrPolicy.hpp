/**
 * @file srcPtrPolicy.hpp
 *
 * @copyright Copyright (C) 2015-2016 srcML, LLC. (www.srcML.org)
 *
 * This file is part of srcPtr.
 *
 * srcPtr is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * srcPtr is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with srcPtr.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef INCLUDED_SRC_PTR_POLICY_HPP
#define INCLUDED_SRC_PTR_POLICY_HPP

#include <DeclDS.hpp>
#include <DeclTypePolicy.hpp>
#include <CallPolicy.hpp>
#include <FunctionSignaturePolicy.hpp>
#include <srcSAXEventDispatcher.hpp>
#include <srcSAXHandler.hpp>

#include <srcPtrDeclPolicy.hpp>
#include <srcPtrUtilities.hpp>

#include <algorithm>
#include <exception>
#include <iostream>
#include <map>
#include <stack>
#include <string>
#include <vector>
#include <utility>
#include <set>

/*
class T must implement:
   void AddPointsToRelationship(Variable, Variable);
   void AddAssignmentRelationship(Variable, Variable);
   void Print();
   void PrintGraphViz();
   std::vector<Variable> GetPointsTo(Variable);
   std::vector<Variable> GetPointers();
   srcPtrData *Clone();
*/

template <class T>
class srcPtrPolicy : public srcSAXEventDispatch::EventListener, public srcSAXEventDispatch::PolicyDispatcher, public srcSAXEventDispatch::PolicyListener {
public:
   
   ~srcPtrPolicy() {
      delete data;
      delete declTypePolicy;
      delete callPolicy;
      delete funcSigPolicy;
   }

   srcPtrPolicy(srcPtrDeclPolicy::srcPtrDeclData decldata, std::initializer_list<srcSAXEventDispatch::PolicyListener *> listeners = {}) : srcSAXEventDispatch::PolicyDispatcher(listeners) {
      declData = decldata;
      declared.CreateFrame();

      declTypePolicy = new DeclTypePolicy({this});
      callPolicy = new CallPolicy({this});
      funcSigPolicy = new FunctionSignaturePolicy({this});

      InitializeEventHandlers();
   }

   void Notify(const PolicyDispatcher *policy, const srcSAXEventDispatch::srcSAXEventContext &ctx) override {
      if (typeid(DeclTypePolicy) == typeid(*policy)) {
         DeclData declarationData = *policy->Data<DeclData>();
         Variable declared_var(declarationData);
         declared_var.filename = ctx.currentFilePath;
         declared.AddVarToFrame(declared_var);

         //If variable is an object, keep track of it's methods and members
         if(declData.classTracker.ContainsKey(declarationData.nameoftype)) {
            Class classType = declData.classTracker.GetClass(declarationData.nameoftype);

            std::string accessor = ".";
            if(declarationData.isPointer)
               accessor = "->";

            for(size_t i = 0; i < classType.methods.size(); ++i) {
               declared.AddFuncToFrame(declarationData.nameofidentifier + accessor + classType.methods[i].name, classType.methods[i]);
            }

            for(size_t i = 0; i < classType.members.size(); ++i) {
               Variable v = classType.members[i];
               std::string newName = declarationData.nameofidentifier + accessor + v.nameofidentifier;
               v.nameofidentifier = newName;
               v.filename = ctx.currentFilePath;
               declared.AddVarToFrame(v);
            }
         }

         // Pointer assignment on initialization: the initializer's names were collected on the left side, because
         // the '=' of an initializer is not an operator element
         if(withinDeclAssignment) {
            Resolve(declared_var, false, lhsSide, declared_var.linenumber, ctx.currentFilePath);
            ResetVariables();
         }
      }

      else if (typeid(CallPolicy) == typeid(*policy)) {
         CallPolicy::CallData callData = *policy->Data<CallPolicy::CallData>();

         struct Arg { std::string name; bool addr = false; };
         struct Frame { std::string fname; bool named = false; std::vector<Arg> args; };
         std::vector<Frame> open, calls;
         for (const std::string &tok : callData.callargumentlist) {
            if (tok == "(") { open.push_back(Frame()); }
            else if (open.empty()) { continue; }
            else if (!open.back().named) { open.back().fname = tok; open.back().named = true; }
            else if (tok == ")") { calls.push_back(open.back()); open.pop_back(); }
            else if (tok == "*ARG*") { open.back().args.push_back(Arg()); }
            else if (tok == "*ADDR*") { if (!open.back().args.empty() && open.back().args.back().name.empty()) open.back().args.back().addr = true; }
            else if (tok == "*LITERAL*") { }
            else {
               if (open.back().args.empty()) open.back().args.push_back(Arg());
               if (open.back().args.back().name.empty()) open.back().args.back().name = tok;   // first name of the argument
            }
         }

         for (const Frame &c : calls) {
            Function called = declared.GetPreviousFuncOccurence(c.fname, c.args.size());
            if(called.name == "")
               called = declData.functionTracker.GetFunction(c.fname, c.args.size());
            if(called.name == "")
               continue;
            for (std::size_t i = 0; i < c.args.size() && i < called.parameters.size(); ++i) {
               if (c.args[i].name.empty()) continue;
               Side side;
               side.names.push_back(c.args[i].name);
               side.isCall.push_back(false);
               side.mod = c.args[i].addr ? "&" : "";
               Resolve(called.parameters[i], false, side, ctx.currentLineNumber, ctx.currentFilePath);
            }
         }
      }

      else if (typeid(FunctionSignaturePolicy) == typeid(*policy)) {
         FunctionSignaturePolicy::SignatureData signatureData = *policy->Data<FunctionSignaturePolicy::SignatureData>();
         Function funcSig = signatureData;
         currentFunction = funcSig.name;
         // only a function that returns a pointer or reference gets a return node
         currentReturnsPointer = funcSig.returnTypeModifier == "*" || funcSig.returnTypeModifier == "&" ||
                                 funcSig.hasAliasedReturn;
         for(Variable var : funcSig.parameters) {
            var.filename = ctx.currentFilePath;
            declared.AddVarToFrame(var);
         }
      }
   }

   T *GetData() {
      T *p = &data;
      return p;
   }

protected:
   void *DataInner() const override {
      return data.Clone();
   }

private:
   T data;

   // Code information
   srcPtrDeclPolicy::srcPtrDeclData declData;
   DeclStack declared;

   // Policies
   DeclTypePolicy *declTypePolicy;
   CallPolicy *callPolicy;
   FunctionSignaturePolicy *funcSigPolicy;

   // For use in collecting assignments. Each side keeps its names in order, which of them name a called function,
   // the leading & or * and whether a member access (-> or .) follows its first name.
   struct Side {
      std::vector<std::string> names;
      std::vector<bool> isCall;
      std::string mod;
      bool member = false;
      bool isNew = false;
   };
   Side lhsSide, rhsSide;

   bool assignmentOperator = false;
   bool withinDeclAssignment = false;
   bool inReturn = false;
   std::string currentFunction;
   bool currentReturnsPointer = false;
   int tmpCount = 0;

   bool collectedClassName = false;

   std::stack<bool> gotClassName;

   void ResetVariables() {
      lhsSide = Side();
      rhsSide = Side();
      assignmentOperator = false;
      withinDeclAssignment = false;
      inReturn = false;
   }

   static bool IsAllocator(const std::string &name) {
      static const std::set<std::string> alloc = {"malloc", "calloc", "realloc", "reallocf", "valloc", "aligned_alloc",
         "strdup", "strndup", "wcsdup", "xmalloc", "xcalloc", "xrealloc", "xstrdup", "g_malloc", "g_malloc0",
         "g_strdup", "kmalloc", "kzalloc", "operator new"};
      return alloc.count(name) > 0;
   }

   static Variable Object(const std::string &kind, const std::string &name, const std::string &file, int line) {
      Variable v;
      v.kind = kind;
      v.nameofidentifier = name;
      v.filename = file;
      v.linenumber = line;
      v.isPointer = (kind == "ret" || kind == "tmp");
      return v;
   }

   // Adds the constraint for  lhs = rhs  (or  *lhs = rhs  when store is set) to the analysis. The first name on the
   // right that means something decides the source: an allocator call (a heap object), a call of a function in the
   // program (its return value), &x (x itself), a function name (that function), *p or p->f (a load through p), a
   // pointer (a copy) or an array (decays to its address). Names that mean nothing here, like cast types, are skipped.
   void Resolve(Variable lhs, bool store, const Side &rhs, int line, const std::string &file) {
      if (lhs.empty())
         return;
      enum { NONE, BASE, COPY, LOAD } how = NONE;
      Variable src;
      if (rhs.isNew) {
         src = Object("heap", "heap@" + std::to_string(line), file, line); how = BASE;
      }
      for (std::size_t i = 0; how == NONE && i < rhs.names.size(); ++i) {
         const std::string &name = rhs.names[i];
         if (rhs.isCall[i]) {
            if (IsAllocator(name)) { src = Object("heap", "heap@" + std::to_string(line), file, line); how = BASE; }
            else if (declData.functionTracker.HasName(name)) { src = Object("ret", "ret@" + name, "", 0); how = COPY; }
            break;   // a library call that allocates nothing: no pointer value we can name
         }
         Variable r = declared.GetPreviousVarOccurence(name);
         if (!r.empty()) {
            if (rhs.mod == "&") how = BASE;
            else if (rhs.mod == "*" || (rhs.member && r.isPointer)) how = LOAD;
            else if (r.isPointer || r.isReference || rhs.member) how = COPY;
            else how = BASE;                       // an array used as a pointer
            src = r;
         } else if (declData.functionTracker.HasName(name)) {
            src = Object("function", name, "", 0); how = BASE;
         }
      }
      if (how == NONE)
         return;
      if (!store && !(lhs.isPointer || lhs.isReference || lhs.kind != "var"))
         return;                                   // not a pointer: nothing to record
      Variable target = lhs;
      if (store)
         target = Object("tmp", "tmp@" + std::to_string(line) + "#" + std::to_string(++tmpCount), file, line);
      if (how == BASE) data.AddPointsToRelationship(target, src);
      else if (how == COPY) data.AddAssignmentRelationship(target, src);
      else data.AddLoadRelationship(target, src);
      if (store)
         data.AddStoreRelationship(lhs, target);
   }

   void ResolveStatement(const srcSAXEventDispatch::srcSAXEventContext &ctx) {
      Variable lhs;
      bool store = false;
      if (inReturn) {
         if (currentFunction.empty() || !currentReturnsPointer) return;
         lhs = Object("ret", "ret@" + currentFunction, "", 0);
      } else {
         for (const std::string &name : lhsSide.names) {
            lhs = declared.GetPreviousVarOccurence(name);
            if (!lhs.empty()) break;
         }
         if (lhs.empty()) return;
         store = (lhsSide.mod == "*") || (lhsSide.member && lhs.isPointer);   // *p = q, p->f = q
         if (lhsSide.member && !lhs.isPointer)
            lhs.isPointer = true;                  // s.f = q: the struct holds the pointer (fields are not told apart)
      }
      Resolve(lhs, store, rhsSide, ctx.currentLineNumber, ctx.currentFilePath);
   }

   void InitializeEventHandlers() {
      using namespace srcSAXEventDispatch;

      openEventMap[ParserState::archive] = [this](srcSAXEventContext &ctx) {
         ctx.dispatcher->AddListenerDispatch(declTypePolicy);
         ctx.dispatcher->AddListenerDispatch(callPolicy);
         ctx.dispatcher->AddListenerDispatch(funcSigPolicy);
      };

      openEventMap[ParserState::block] = [this](srcSAXEventContext &ctx) { declared.CreateFrame(); };
      closeEventMap[ParserState::block] = [this](srcSAXEventContext &ctx) { declared.PopFrame(); };
      // a function's parameters live in a frame of their own (they used to land in the enclosing frame, which keeps
      // the first variable of a name, so a later function's parameter p resolved to an earlier function's p)
      openEventMap[ParserState::function] = [this](srcSAXEventContext &ctx) { declared.CreateFrame(); };
      closeEventMap[ParserState::function] = [this](srcSAXEventContext &ctx) { declared.PopFrame(); currentFunction.clear(); };

      //
      // Collecting pointer assignment data
      //

      openEventMap[ParserState::exprstmt] = [this](srcSAXEventContext &ctx) { ResetVariables(); };
      openEventMap[ParserState::declstmt] = [this](srcSAXEventContext &ctx) { ResetVariables(); };
      openEventMap[ParserState::returnstmt] = [this](srcSAXEventContext &ctx) {
         ResetVariables();
         assignmentOperator = true;                // return x;  is  ret@f = x
         inReturn = true;
      };

      closeEventMap[ParserState::tokenstring] = [this](srcSAXEventContext &ctx) {
         // operators inside a compound name (s.buf, p->next) also arrive here while the name is open: skip them
         if (ctx.IsOpen(ParserState::expr) && ctx.IsOpen(ParserState::name) && !ctx.IsOpen(ParserState::op)) {
            Side &side = assignmentOperator ? rhsSide : lhsSide;
            side.names.push_back(ctx.currentToken);
            side.isCall.push_back(ctx.IsOpen(ParserState::call) && ctx.IsGreaterThan(ParserState::call, ParserState::argumentlist));
         }
      };

      closeEventMap[ParserState::op] = [this](srcSAXEventContext &ctx) {
         const std::string &tok = ctx.currentToken;
         Side &side = assignmentOperator ? rhsSide : lhsSide;
         if (tok == "=" && !lhsSide.names.empty() && !assignmentOperator)
            assignmentOperator = true;
         // member access is an operator inside a compound name; "->" can arrive as "-" then ">"
         else if (ctx.IsOpen(ParserState::name) && (tok == "->" || tok == "." || tok == ">") && side.names.size() == 1)
            side.member = true;
         else if ((tok == "&" || tok == "*") && side.names.empty() && side.mod.empty())
            side.mod = tok;
         else if (tok == "new" && side.names.empty())
            side.isNew = true;
      };

      // p[i] reads an element through p, like *p (fields and elements are not told apart)
      openEventMap[ParserState::index] = [this](srcSAXEventContext &ctx) {
         if (!ctx.IsOpen(ParserState::expr)) return;
         Side &side = assignmentOperator ? rhsSide : lhsSide;
         if (side.names.size() == 1)
            side.member = true;
      };

      closeEventMap[ParserState::init] = [this](srcSAXEventContext &ctx) {
         withinDeclAssignment = true;
      };

      closeEventMap[ParserState::exprstmt] = [this](srcSAXEventContext &ctx) {
         if(assignmentOperator)
            ResolveStatement(ctx);
         ResetVariables();
      };

      closeEventMap[ParserState::returnstmt] = [this](srcSAXEventContext &ctx) {
         if (inReturn)
            ResolveStatement(ctx);
         ResetVariables();
      };

      closeEventMap[ParserState::archive] = [this](srcSAXEventContext &ctx) { // End of Policy
         ctx.dispatcher->RemoveListenerDispatch(declTypePolicy);
         ctx.dispatcher->RemoveListenerDispatch(callPolicy);
         ctx.dispatcher->RemoveListenerDispatch(funcSigPolicy);
         NotifyAll(ctx);
      };

      closeEventMap[ParserState::name] = [this](srcSAXEventContext& ctx) {
         if (ctx.IsOpen(ParserState::classn)) {
            if (!gotClassName.top()) {
               Class current = declData.classTracker.GetClass(ctx.currentToken);

               if(current.className != "") {
                  for(Function f : current.methods) {
                     declared.AddFuncToFrame(f);
                  }
                  for(Variable v : current.members) {
                     declared.AddVarToFrame(v);

                     //If variable is an object, keep track of it's methods and members
                     if(declData.classTracker.ContainsKey(v.nameoftype)) {
                        Class classType = declData.classTracker.GetClass(v.nameoftype);

                        std::string accessor = ".";
                        if(v.isPointer)
                           accessor = "->";

                        for(size_t i = 0; i < classType.methods.size(); ++i) {
                           declared.AddFuncToFrame(v.nameofidentifier + accessor + classType.methods[i].name, classType.methods[i]);
                        }

                        for(size_t i = 0; i < classType.members.size(); ++i) {
                           Variable v = classType.members[i];
                           std::string newName = v.nameofidentifier + accessor + v.nameofidentifier;
                           v.nameofidentifier = newName;
                           declared.AddVarToFrame(v);
                        }
                     }

                  }
               }

               gotClassName.top() = true;
            }
         }

      };

      openEventMap[ParserState::classn] = [this](srcSAXEventContext& ctx) {
         gotClassName.push(false);
      };

      closeEventMap[ParserState::classn] = [this](srcSAXEventContext& ctx) {
         gotClassName.pop();
      };

      openEventMap[ParserState::structn] = [this](srcSAXEventContext& ctx) {
         gotClassName.push(false);
      };

      closeEventMap[ParserState::structn] = [this](srcSAXEventContext& ctx) {
         gotClassName.pop();
      };
   }
};

#endif
