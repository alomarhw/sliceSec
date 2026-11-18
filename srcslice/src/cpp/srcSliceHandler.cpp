/**
 * @file srcSliceHandler.cpp
 *
 * @copyright Copyright (C) 2013-2014 SDML (www.srcML.org)
 *
 * The srcML Toolkit is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * The srcML Toolkit is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the srcML Toolkit; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <srcSliceHandler.hpp>
#include <Utility.hpp>
#include <algorithm>
#include <cctype>
/**
 *Find
 *Find function takes a variable name and searches first the local table to the function it was in
 *and if it's not found there, then it searches the global table to see if it's in there.
 *If neither has the variable, it returns null otherwise returns a pointer to the slice profile
 *@param varName - Name of the variable whose slice profile we want.
 *@return Pointer to Slice Profile or null.
 */
SliceProfile* srcSliceHandler::FindLocal(const std::string& varName){
    auto sp = FunctionIt->second.find(varName);
    if(sp != FunctionIt->second.end()){
        return &(sp->second);
    }else{ //check global map
        auto sp2 = sysDict->globalMap.find(varName);
        if(sp2 != sysDict->globalMap.end()){
            return &(sp2->second);
        }
    }
    return nullptr;
}

/**
 * Find
 * The profile a read of varName refers to: the current function's, a global declaration's, or else the
 * file-scope variable of that name (a module variable read inside a Python function). A definition uses
 * FindLocal instead, so an assignment inside a function still makes a local.
 */
SliceProfile* srcSliceHandler::Find(const std::string& varName){
    if(SliceProfile* sp = FindLocal(varName)){
        return sp;
    }
    auto file = FileIt->second.find("GLOBAL");
    if(file != FileIt->second.end() && &(file->second) != &(FunctionIt->second)){
        auto sp = file->second.find(varName);
        if(sp != file->second.end()){
            return &(sp->second);
        }
    }
    return nullptr;
}
/**
 *ProcessConstructorDecl
 *Processes decls of the form object(arg,arg)
 */
void srcSliceHandler::ProcessConstructorDecl(){
    auto sp = Find(currentDeclArg.first);
    if(sp){
        sp->dvars.insert(varIt->second.variableName);
    }
}

/*
*ProcessDeclStmt
*Takes rhs of decl_stmt and processes it. Split by tokens and then throw against the map for an answer.
*corner case at new operator because new makes an object even if its argument is an alias.
*/
void srcSliceHandler::ProcessDeclStmt(){
    if(currentDeclInit.first == ""){return;} //No nameless profiles.
    auto sp = Find(currentDeclInit.first);
    if(sawnew){sawnew = false;}
    if(sp){
        varIt->second.slines.insert(currentDeclInit.second); //varIt is lhs
        sp->use.insert(currentDeclInit.second);
        if(varIt->second.potentialAlias && !sawnew){ //new operator of the form int i = new int(tmp); screws around with aliasing
            varIt->second.lastInsertedAlias = varIt->second.aliases.insert(sp->variableName).first;
        }else{
            sp->dvars.insert(varIt->second.variableName);
            sp->use.insert(currentDeclInit.second);
        }
    }else{ //Inits in for loops screw with typical decl statement handling. This will grab decls I miss due to weird init usage
        if(!inFor) return; //This really is only for for loop inits. TODO: Possibly, write a separate function for these.
        currentSliceProfile.index = 0;
        varIt = FunctionIt->second.insert(std::make_pair(currentDeclInit.first, std::move(currentSliceProfile))).first;
        varIt->second.def.insert(currentDeclInit.second);    
    } 
    currentDeclInit.first.clear();
}

/*
* GetCallData
* Knows the proper constrains for obtaining the name of arguments of currently called function
* It stores data about those variables if it can find a slice profile entry for them.
* Essentially, update the slice profile of the argument to reflect new data.
*/
void srcSliceHandler::GetCallData(){
    //Get function arguments
    if(triggerField[argument_list] && triggerField[argument] && 
        triggerField[expr] && triggerField[name] && !nameOfCurrentClldFcn.empty() && !triggerField[sizeofop]){
        if(!callArgData.empty()){
            const std::string keyword = argKeyword.empty() ? std::string() : argKeyword.top();
            const bool method = !calleeIsMethod.empty() && calleeIsMethod.top();
            auto sp = Find(callArgData.top().first); //check to find sp for the variable being called on fcn
            if(sp){
                LinkCallArg(sp, callArgData.top().second, nameOfCurrentClldFcn.top(), numArgs, keyword, method);
                //int r = f(x); makes r depend on x, the same as r = f(x); already does
                if(triggerField[decl_stmt] && triggerField[init] && !inGlobalScope && sp->variableName != varIt->second.variableName){
                    sp->dvars.insert(varIt->second.variableName);
                }
            }else if(!callArgData.top().first.empty()){
                //may be bound later in the same statement: [f(e) for e in xs]
                pendingArgs.push_back(PendingArg{callArgData.top(), nameOfCurrentClldFcn.top(), numArgs, keyword, method});
            }
        }
    }
}

void srcSliceHandler::GetParamType(){
    currentSliceProfile.variableType = currentParamType.first;
    currentParamType.first.clear();
}

void srcSliceHandler::GetParamName(){
    if(currentParam.first.empty()){ //def f(a, *, b) / def f(a, /, b): the marker binds nothing
        return;
    }
    currentSliceProfile.index = triggerField[parameter_list] == 1 ? paramIndex : 0;
    currentSliceProfile.file = fileName;
    currentSliceProfile.function = functionTmplt.functionName;
    currentSliceProfile.variableName = currentParam.first;
    currentSliceProfile.potentialAlias = potentialAlias;
    currentSliceProfile.isGlobal = inGlobalScope;

    varIt = FunctionIt->second.insert(std::make_pair(currentParam.first, std::move(currentSliceProfile))).first;
    varIt->second.def.insert(currentParam.second);

    currentParam.first.clear();
}

/**
* GetFunctionData
* Knows proper constraints for obtaining function's return type, name, and arguments. Stores all of this in
* functionTmplt.
*/
void srcSliceHandler::GetFunctionData(){
    //Get function name
    if(isConstructor){
        std::stringstream ststrm;
        ststrm<<constructorNum;
        currentFunctionBody.first+=ststrm.str(); //number the constructor. Find a better way than stringstreams someday.
    }
    functionTmplt.functionName = currentFunctionBody.first;
    currentFunctionBody.first.clear();
}

void srcSliceHandler::GetFunctionDeclData(){
    functionTmplt.params.push_back(currentParamType.first);
}
void srcSliceHandler::AssignProfile(){
    if(currentSliceProfile.file.empty()){
        currentSliceProfile.file = fileName;
    }
    if(currentSliceProfile.function.empty()){
        currentSliceProfile.function = functionTmplt.functionName;
    }
    if(currentSliceProfile.variableName.empty()){
        currentSliceProfile.variableName = currentDecl.first;
        //std::cerr<<currentDecl.first<<std::endl;
    }
    if(!currentSliceProfile.potentialAlias){
        currentSliceProfile.potentialAlias = potentialAlias;
    }
    if(!currentSliceProfile.isGlobal){
        currentSliceProfile.isGlobal = inGlobalScope;
    }
}
/**
* GetDeclStmtData
* Knows proper constraints for obtaining DeclStmt type and name.
* creates a new slice profile and stores data about decle statement inside.
*/
void srcSliceHandler::GetDeclStmtData(){
    if(currentDecl.first.empty()) return;
    currentSliceProfile.index = 0; //only parameters carry an index
    currentSliceProfile.file = fileName;
    currentSliceProfile.function = functionTmplt.functionName;
    currentSliceProfile.variableName = currentDecl.first;
    //std::cerr<<currentDecl.first<<std::endl;
    currentSliceProfile.potentialAlias = potentialAlias;
    currentSliceProfile.isGlobal = inGlobalScope;
    if(!inGlobalScope){
        varIt = FunctionIt->second.insert(std::make_pair(currentSliceProfile.variableName, std::move(currentSliceProfile))).first;
        varIt->second.def.insert(currentDecl.second);
    }else{ //TODO: Handle def use for globals
        sysDict->globalMap.insert(std::make_pair(currentSliceProfile.variableName, std::move(currentSliceProfile)));
    }
    currentDecl.first.clear();
}

/**
 * ProcessExprStmt
 * Get entire expression statement and then process by first splitting to lhs and rhs. Process the lhs
 * by saving its slines if it can be found in the map. After lhs is processed, keep track of it and then
 * process the rhs for any aliases, dvars, or function calls.
 */
void srcSliceHandler::ProcessExprStmtPreAssign(){
    if(!lhsExprStmt.first.empty()){
        SliceProfile* lhs = FindLocal(lhsExprStmt.first);
        if(!lhs){
            currentSliceProfile.index = 0;
            currentSliceProfile.file = fileName;
            currentSliceProfile.function = functionTmplt.functionName;
            currentSliceProfile.variableName = lhsExprStmt.first;
            currentSliceProfile.potentialAlias = false;
            currentSliceProfile.isGlobal = inGlobalScope;
            
            varIt = FunctionIt->second.insert(std::make_pair(lhsExprStmt.first, std::move(currentSliceProfile))).first;
            varIt->second.def.insert(lhsExprStmt.second);
        }else{
            lhs->def.insert(lhsExprStmt.second);
        }        
    }
}

/**
 * ProcessExprStmt
 * Get entire expression statement and then process by first splitting to lhs and rhs. Process the lhs
 * by saving its slines if it can be found in the map. After lhs is processed, keep track of it and then
 * process the rhs for any aliases, dvars, or function calls.
 */
void srcSliceHandler::ProcessExprStmtPostAssign(){
    ProcessExprStmtPostAssignTo(lhsName);
    for(const std::string& target : lhsNames){ //a, b = x: x reaches every target
        ProcessExprStmtPostAssignTo(target);
    }
}

void srcSliceHandler::ProcessExprStmtPostAssignTo(const std::string& lhsVar){
    SliceProfile* lhs = Find(lhsVar);
    if(!lhs){return;}

    auto sprIt = Find(currentExprStmt.first);//find the sp for the rhs
    if(sprIt){ //lvalue depends on this rvalue
        if(lhs->variableName != sprIt->variableName){    
            if(!lhs->potentialAlias || dereferenced){ //It is not potentially a reference and if it is, it must not have been dereferenced
                sprIt->dvars.insert(lhs->variableName); //it's not an alias so it's a dvar
            }else{//it is an alias, so save that this is the most recent alias and insert it into rhs alias list
                lhs->lastInsertedAlias = lhs->aliases.insert(sprIt->variableName).first;
            }
            sprIt->use.insert(currentExprStmt.second);           
            if(sprIt->potentialAlias && !dereferenced){//Union things together. If this was an alias of anoter thing, update the other thing
                if(!sprIt->aliases.empty()){
                    auto spaIt = FunctionIt->second.find(*(sprIt->lastInsertedAlias)); //problem  because last alias is an iterator and can reference things in other functions. Maybe make into a pointer. Figure out why I need it.
                    if(spaIt != FunctionIt->second.end()){
                        spaIt->second.dvars.insert(lhs->variableName);
                        spaIt->second.use.insert(currentExprStmt.second);  
                        spaIt->second.slines.insert(currentExprStmt.second);
                    }
                }
            }
        }
    }
}
void srcSliceHandler::ProcessExprStmtNoAssign(){
    for(NameLineNumberPair name : useExprStack){
        SliceProfile* useProfile = Find(name.first);
        if(!useProfile){continue;}
        else{//it's running on the same word as the other two exprstmt functions
            useProfile->use.insert(name.second);
        }        
    }

}
void srcSliceHandler::ProcessDeclCtor(){
    SliceProfile* lhs = Find(currentDecl.first);
    if(!lhs){
        return;
    }else{
        lhs->use.insert(currentDecl.second);
    }
    SliceProfile* rhs = Find(currentDeclCtor.first);
    if(rhs){
        //std::cerr<<lhs->variableName<<std::endl;
        rhs->dvars.insert(lhs->variableName);
        rhs->use.insert(currentDecl.second);
    }
    
}

/*
 *ComputeInterprocedural
 *@param f- name of the file
 *No return value
 */
void srcSliceHandler::ComputeInterprocedural(const std::string& f){   
    FileIt = sysDict->ffvMap.find(f);
    if(FileIt == sysDict->ffvMap.end()){
        //std::cerr<<"CAN'T FIND FILE"<<std::endl;
        return;
    }
    FunctionIt = (FileIt)->second.begin();
    FunctionVarMap::iterator FunctionItEnd = FileIt->second.end();

    for(FunctionIt; FunctionIt != FunctionItEnd; ++FunctionIt){
        for(VarMap::iterator it = FunctionIt->second.begin(); it != FunctionIt->second.end(); ++it){
            if(it->second.visited == false){//std::unordered_set<NameLineNumberPair, NameLineNumberPairHash>::iterator - auto       
                for(auto itCF = it->second.cfunctions.begin(); itCF != it->second.cfunctions.end(); ++itCF ){
                    unsigned int argumentIndex = itCF->second;
                    SliceProfile Spi = ArgumentProfile(itCF->first, argumentIndex, it);
                    SetUnion(it->second.use, Spi.def);
                    SetUnion(it->second.use, Spi.use);
                    SetUnion(it->second.cfunctions, Spi.cfunctions);
                    SetUnion(it->second.dvars, Spi.dvars);
                    //SetUnion(it->second.aliases, Spi.aliases); //I suspect this is wrong, but I'll leave it here in case I'm wrong.
                }
                it->second.visited = true;
            } 
        }
    }  
}

/*
 *ArgumentProfile
 *@param functIt- iterator to the FunctionVarMap, parameterIndex- index of the parameter 
 *@Return SliceProfile of the variable
*/
SliceProfile srcSliceHandler::ArgumentProfile(std::string fname, unsigned int parameterIndex, VarMap::iterator vIt){ //TODO varIt is a hack here. Fix. We shouldn't need to pass an extra param to do this.
    SliceProfile Spi;
    if(parameterIndex == 0){return Spi;}
    //look the callee up without moving FileIt, which ComputeInterprocedural is still iterating over
    FileFunctionVarMap::iterator calleeFileIt = FileIt;
    auto gFuncIt = sysDict->fileFunctionTable.find(fname);
    if(gFuncIt != sysDict->fileFunctionTable.end()){
        calleeFileIt = sysDict->ffvMap.find(gFuncIt->second.fileName);
        if(calleeFileIt == sysDict->ffvMap.end()){return Spi;}
    }
    auto funcIt = calleeFileIt->second.find(fname);
    if(funcIt != calleeFileIt->second.end()){
        VarMap::iterator v = funcIt->second.begin();    
        for(VarMap::iterator it = v; it != funcIt->second.end(); ++it){
        
            if (it->second.index == (parameterIndex)){
                if(it->second.visited == true){
                    if(it->second.potentialAlias){
                        it->second.aliases.insert(vIt->second.variableName);
                    }
                    return it->second;
                }else{
                    for(auto itCF = it->second.cfunctions.begin(); itCF != it->second.cfunctions.end(); ++itCF ){
                        std::string newFunctionName = itCF->first;
                        unsigned int newParameterIndex = itCF->second;
                        if(newFunctionName != fname){
                            it->second.visited = true;
                            Spi = ArgumentProfile(newFunctionName, newParameterIndex, it);
                            SetUnion(it->second.use, Spi.def);
                            SetUnion(it->second.use, Spi.use);
                            SetUnion(it->second.cfunctions, Spi.cfunctions);
                            SetUnion(it->second.dvars, Spi.dvars);
                            SetUnion(it->second.aliases, Spi.aliases);
                        }
                    }
                    if(it->second.potentialAlias){
                        it->second.aliases.insert(vIt->second.variableName);
                    }
                    it->second.visited = true;
                    return it->second;
                }
            }
        }
    }else{
        //uncomment to see errors. Need to handle this properly. Also, currently, a lot of these misses are calls 
        //into functions in header files or libraries that I can't see. Running preprocessor before srcML should
        //help but will also make things messy.
        //std::cout<<"ERROR IN ARGUMENT PROFILE WHEN ACCESSING: "<<fname<<std::endl;
    }
    return Spi;
}

/**
 * LastIndexOf
 * Position of the innermost open element named element at or after from, or -1.
 */
long srcSliceHandler::LastIndexOf(const std::string& element, std::size_t from) const {
    for(std::size_t i = elementPath.size(); i > from; --i){
        if(elementPath[i - 1] == element){
            return static_cast<long>(i - 1);
        }
    }
    return -1;
}

/**
 * IsCalleeName
 * The <name> being closed names the function of a call (f or obj.m in obj.m(x)), not a variable.
 */
bool srcSliceHandler::IsCalleeName() const {
    long callPos = LastIndexOf("call");
    return callPos >= 0 && LastIndexOf("argument_list", callPos) < 0;
}

/**
 * FindOrDefine
 * Slice profile of a variable bound by a binding form, created on first binding (Python has no declarations).
 */
SliceProfile* srcSliceHandler::FindOrDefine(const std::string& varName, unsigned int line){
    SliceProfile* sp = FindLocal(varName);
    if(!sp){
        SliceProfile profile(0, fileName, functionTmplt.functionName, line, varName, false, inGlobalScope);
        sp = &(FunctionIt->second.insert(std::make_pair(varName, std::move(profile))).first->second);
    }
    sp->def.insert(line);
    return sp;
}

/**
 * OnBaseName
 * A variable read or written by a binding form: for-in targets and iterables, with ... as aliases and their sources.
 */
void srcSliceHandler::OnBaseName(const std::string& varName, unsigned int line){
    if(IsCalleeName() || LastIndexOf("type") >= 0 || LastIndexOf("annotation") >= 0 || LastIndexOf("parameter_list") >= 0){
        return;
    }
    long declAt = LastIndexOf("decl");
    bool inInit = declAt >= 0 && LastIndexOf("init", declAt) >= 0;
    if(LastIndexOf("index") >= 0 && (declAt < 0 || inInit)){ //a subscript reads its index: q[a], x = v[i], int y = r[k]
        if(SliceProfile* sp = Find(varName)){
            sp->use.insert(line);
            if(inInit && varIt->second.variableName != varName){ //int y = r[k]: y depends on k
                sp->dvars.insert(varIt->second.variableName);
            }
            if(exprassign){ //on the right of an assignment, the targets depend on the index
                for(const std::string& target : lhsNames){
                    if(target != varName) sp->dvars.insert(target);
                }
                if(!lhsName.empty() && lhsName != varName) sp->dvars.insert(lhsName);
            }
        }
    }
    for(auto ctx = forBindings.rbegin(); ctx != forBindings.rend(); ++ctx){
        long control = LastIndexOf("control", ctx->depth);
        if(control < 0 || LastIndexOf("block", ctx->depth) >= 0){
            continue;
        }
        if(LastIndexOf("range", control) >= 0){
            ctx->sources.push_back(std::make_pair(varName, line));
        }else if(LastIndexOf("call", control) < 0 && LastIndexOf("index", control) < 0){
            ctx->targets.push_back(std::make_pair(varName, line));
        }
        return;
    }
    if(!withBindings.empty() && LastIndexOf("block", withBindings.back().depth) < 0){
        BindingContext& ctx = withBindings.back();
        if(LastIndexOf("alias", ctx.depth) >= 0){
            ctx.targets.push_back(std::make_pair(varName, line));
        }else{
            ctx.sources.push_back(std::make_pair(varName, line)); //with open(path) as fh: fh comes from path, as in fh = open(path)
        }
    }
}

/**
 * ApplyBinding
 * Define every target and make it depend on every source.
 */
void srcSliceHandler::ApplyBinding(BindingContext& ctx){
    std::vector<std::string> targets;
    for(const NameLineNumberPair& target : ctx.targets){
        FindOrDefine(target.first, target.second);
        targets.push_back(target.first);
    }
    for(const NameLineNumberPair& source : ctx.sources){
        SliceProfile* sp = Find(source.first);
        if(!sp){
            continue;
        }
        sp->use.insert(source.second);
        for(const std::string& target : targets){
            if(target != sp->variableName){
                sp->dvars.insert(target);
            }
        }
    }
}

/**
 * LinkCallArg
 * Record that sp is passed to callee at argument position pos (or as keyword argument keyword).
 */
void srcSliceHandler::LinkCallArg(SliceProfile* sp, unsigned int line, const std::string& callee, unsigned int pos, const std::string& keyword, bool method){
    sp->slines.insert(line);
    sp->use.insert(line);
    if(pos == 0 && keyword.empty()){ //receiver of a call inside an argument (f(x.read())): read, not passed to f
        return;
    }
    if(keyword.empty() && !method){
        sp->cfunctions.insert(std::make_pair(callee, pos));
    }else{
        pendingCalls.push_back(PendingCall{sp, callee, pos, keyword, method});
    }
}

/**
 * RetryPendingArgs
 * Link call arguments whose variable was only bound later in the statement.
 */
void srcSliceHandler::RetryPendingArgs(){
    for(const PendingArg& arg : pendingArgs){
        if(SliceProfile* sp = Find(arg.arg.first)){
            LinkCallArg(sp, arg.arg.second, arg.callee, arg.pos, arg.keyword, arg.method);
        }
    }
    pendingArgs.clear();
}

/**
 * ResolvePendingCalls
 * After parsing: keyword arguments take the position of the callee parameter with that name, and in a method
 * call obj.m(x) the receiver fills self/cls, so argument k is parameter k+1. Callees outside the archive keep the
 * call position; their keyword arguments cannot be placed and only count as uses.
 */
void srcSliceHandler::ResolvePendingCalls(){
    for(const PendingCall& call : pendingCalls){
        const VarMap* callee = nullptr;
        auto fn = sysDict->fileFunctionTable.find(call.callee);
        if(fn != sysDict->fileFunctionTable.end()){
            auto file = sysDict->ffvMap.find(fn->second.fileName);
            if(file != sysDict->ffvMap.end()){
                auto vars = file->second.find(call.callee);
                if(vars != file->second.end()){
                    callee = &vars->second;
                }
            }
        }
        if(!call.keyword.empty()){
            if(callee){
                auto param = callee->find(call.keyword);
                if(param != callee->end() && param->second.index > 0){
                    call.sp->cfunctions.insert(std::make_pair(call.callee, param->second.index));
                }
            }
            continue;
        }
        unsigned int pos = call.pos;
        if(call.method && callee){
            for(const auto& param : *callee){
                if(param.second.index == 1 && (param.first == "self" || param.first == "cls")){
                    ++pos;
                    break;
                }
            }
        }
        call.sp->cfunctions.insert(std::make_pair(call.callee, pos));
    }
    pendingCalls.clear();
}

/**
 * ProcessFString
 * srcML keeps an f-string as one literal, so read the variables and simple calls in its {...} fields.
 */
void srcSliceHandler::ProcessFString(const std::string& text, unsigned int line){
    std::size_t quote = text.find_first_of("\"'");
    if(quote == std::string::npos || text.substr(0, quote).find_first_of("fF") == std::string::npos){
        return;
    }
    auto isStart = [](char c){ return std::isalpha(static_cast<unsigned char>(c)) || c == '_'; };
    auto isPart = [](char c){ return std::isalnum(static_cast<unsigned char>(c)) || c == '_'; };
    auto lineAt = [&](std::size_t pos){ return line + static_cast<unsigned int>(std::count(text.begin(), text.begin() + pos, '\n')); };
    auto use = [&](const std::string& var, unsigned int at){
        SliceProfile* sp = Find(var);
        if(!sp){
            return static_cast<SliceProfile*>(nullptr);
        }
        sp->use.insert(at);
        if(exprassign){
            for(const std::string& target : lhsNames){
                if(target != var) sp->dvars.insert(target);
            }
            if(!lhsName.empty() && lhsName != var) sp->dvars.insert(lhsName);
        }
        return sp;
    };
    for(std::size_t i = quote; i < text.size(); ++i){
        if(text[i] != '{'){
            continue;
        }
        if(i + 1 < text.size() && text[i + 1] == '{'){ //{{ is a literal brace
            ++i;
            continue;
        }
        //the field runs to the matching } (format spec after : or ! at depth 0 is not code)
        std::size_t end = i + 1;
        int depth = 0;
        for(; end < text.size(); ++end){
            char c = text[end];
            if(c == '(' || c == '[' || c == '{') ++depth;
            else if(c == ')' || c == ']') --depth;
            else if(c == '}'){ if(depth == 0) break; --depth; }
            else if((c == ':' || c == '!') && depth == 0 && !(c == '!' && end + 1 < text.size() && text[end + 1] == '=')) break;
        }
        std::string field = text.substr(i + 1, end - i - 1);
        unsigned int at = lineAt(i);
        for(std::size_t k = 0; k < field.size();){
            if(!isStart(field[k]) || (k > 0 && (isPart(field[k - 1]) || field[k - 1] == '.'))){
                ++k;
                continue;
            }
            std::size_t e = k;
            while(e < field.size() && isPart(field[e])) ++e;
            std::string ident = field.substr(k, e - k);
            std::size_t next = field.find_first_not_of(" \t", e);
            if(next != std::string::npos && field[next] == '('){
                //simple call: link the variables that start each argument
                bool method = k > 0 && field[k - 1] == '.';
                unsigned int argPos = 1;
                int d = 0;
                bool atArgStart = true;
                std::size_t a = next + 1;
                for(; a < field.size(); ++a){
                    char c = field[a];
                    if(c == '(' || c == '[' || c == '{'){ ++d; atArgStart = false; }
                    else if(c == ')' || c == ']' || c == '}'){ if(d == 0) break; --d; }
                    else if(c == ',' && d == 0){ ++argPos; atArgStart = true; }
                    else if(atArgStart && d == 0 && isStart(c)){
                        std::size_t ae = a;
                        while(ae < field.size() && isPart(field[ae])) ++ae;
                        if(SliceProfile* sp = use(field.substr(a, ae - a), at)){
                            LinkCallArg(sp, at, ident, argPos, std::string(), method);
                        }
                        atArgStart = false;
                        a = ae - 1;
                    }else if(c != ' ' && c != '\t'){
                        atArgStart = false;
                    }
                }
                k = a;
                continue;
            }
            use(ident, at);
            k = e;
        }
        i = end;
    }
}
