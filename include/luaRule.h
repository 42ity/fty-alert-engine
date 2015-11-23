#ifndef __include_luaRule__
#define __include_luaRule__

#include "rule.h"
extern "C" {
#include<lua.h>
}

class luaRule : public Rule {
 public:
    /**
     * \brief set the evaluation code
     */
    luaRule () {};
    luaRule (const luaRule &r);
    virtual void code (const std::string &newCode);
    std::string code () { return _code; };
    void globalVariables (const std::map<std::string,double> &vars);
    virtual int evaluate (const MetricList &metricList, PureAlert **pureAlert);
    double evaluate(const std::vector<double> &metrics);
    virtual ~luaRule () { if (_lstate) lua_close (_lstate); }
 protected:
    void _setGlobalVariablesToLUA();
    
    //TODO: remove _lua_code from parent
    std::string _code;
    bool _valid = false;
    lua_State *_lstate = NULL;
};

#endif // __include_luaRule__
