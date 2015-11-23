#include "luaRule.h"

extern "C" {
#include<lualib.h>
#include<lauxlib.h>
}

luaRule::luaRule (const luaRule &r)
{
    _rule_name = r._rule_name;
    globalVariables (r._values);
    code (r._code);
}


void luaRule::globalVariables (const std::map<std::string,double> &vars)
{
    _values.clear ();
    _values.insert (vars.cbegin (), vars.cend ());
    _setGlobalVariablesToLUA();
}

void luaRule::code (const std::string &newCode)
{
    if (_lstate) lua_close (_lstate);
    _valid = false;
    _code.clear();
    
    _lstate = lua_open();
    if (! _lstate) {
        throw std::runtime_error("Can't initiate LUA context!");
    }
    luaL_openlibs(_lstate); // get functions like print();
    
    // set global variables
    _setGlobalVariablesToLUA();

    // set code, try to compile it
    _code = newCode;
    int error = luaL_dostring (_lstate, _code.c_str());
    _valid = (error == 0);
    if (! _valid) {
        throw std::runtime_error("Invalid LUA code!");
    }

    // check wether there is main() function
    lua_getglobal (_lstate, "main");
    if (! lua_isfunction (_lstate, lua_gettop (_lstate))) {
        // main() missing
        _valid = false;
        throw std::runtime_error("Function main not found!");
    }
}

int luaRule::evaluate (const MetricList &metricList, PureAlert **pureAlert)
{
    return 0;
}

double luaRule::evaluate(const std::vector<double> &metrics)
{
    double result;
    
    if (! _valid) { throw std::runtime_error("Rule is not valid!"); }
    lua_settop (_lstate, 0);
        
    lua_getglobal (_lstate, "main");
    for (const auto x: metrics) {
        lua_pushnumber (_lstate, x);
    }
    if (lua_pcall (_lstate, metrics.size (), 1, 0) != 0) {
        throw std::runtime_error("LUA calling main() failed!");
    }
    if (!lua_isnumber (_lstate, -1)) {
        throw std::runtime_error("LUA main function did not returned number!");
    }
    result = lua_tonumber (_lstate, -1);
    lua_pop (_lstate, 1);
    return result;
}

void luaRule::_setGlobalVariablesToLUA()
{
    if (_lstate == NULL) return;
    for (const auto &it : _values) {
        lua_pushnumber (_lstate, it.second);
        lua_setglobal (_lstate, it.first.c_str ());
    }
}
