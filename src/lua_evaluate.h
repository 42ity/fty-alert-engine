/*  =========================================================================
    lua_evaluate - Lua evaluator decorator

    Copyright (C) 2019 - 2019 Eaton

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
    =========================================================================
*/

#ifndef LUA_EVALUATE_H_INCLUDED
#define LUA_EVALUATE_H_INCLUDED

#include <map>
#include <string>
#include <vector>
#include <cxxtools/serializationinfo.h>

extern "C" {
#include <lua.h>
}

#ifdef __cplusplus
extern "C" {
#endif

///  Self test of this class
FTY_ALERT_ENGINE_PRIVATE void
    lua_evaluate_test (bool verbose);
//  @end

#ifdef __cplusplus
}
#endif

class lua_exception : public std::runtime_error {
    public:
        lua_exception (std::string reason) : runtime_error (reason) { }
};
class cant_initiate : public lua_exception {
    public:
        cant_initiate () : lua_exception ("Can't initiate LUA context!") { }
};
class invalid_code : public lua_exception {
    public:
        invalid_code () : lua_exception ("Invalid LUA code!") { }
};
class missing_main : public lua_exception {
    public:
        missing_main () : lua_exception ("Function main not found!") { }
};
class main_returns_nonstring : public lua_exception {
    public:
        main_returns_nonstring () : lua_exception ("LUA main function did not return string!") { }
};
class evaluation_failed: public lua_exception {
    public:
        evaluation_failed () : lua_exception ("LUA evaluation failed!") { }
};


class DecoratorLuaEvaluate {
    public:
        typedef std::map<std::string, std::string> VariableMap;
        typedef std::vector<std::string> VectorStrings;
    public:
        DecoratorLuaEvaluate () : outcome_items_(1) { };
        DecoratorLuaEvaluate (const DecoratorLuaEvaluate &r) : global_variables_ (r.global_variables_),
                code_ (r.code_), outcome_items_(1) { } ;
        /// get number of outcome variables (size of evaluation result)
        int getOutcomeItems () const { return outcome_items_; };
        /// get number of outcome variables (size of evaluation result)
         void setOutcomeItems (int count) { outcome_items_ = count; };
        /// get lua code
        std::string getCode () const { return code_; };
        /// set new code and reinitialize LUA stack
        void setCode (const std::string newCode);
        /// set global variables in lua code
        void setGlobalVariables (const VariableMap vars);
        VariableMap &getGlobalVariables () { return global_variables_; };
        /// evaluate code with respect to input arguments
        VectorStrings evaluate (const std::vector<std::string> &arguments);
        ~DecoratorLuaEvaluate ();
        //internal functions
    protected:
        /// global variables initialization in lua
        void setGlobalVariablesToLUAStack ();

        VariableMap global_variables_;
        bool valid_ = false;
        lua_State *lstate_ = NULL;
    private:
        /// plain code
        std::string code_;
        /// count of outcome elements
        int outcome_items_;
};

#endif
