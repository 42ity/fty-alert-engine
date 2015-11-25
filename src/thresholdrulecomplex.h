/*
Copyright (C) 2014 - 2015 Eaton

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
*/

/*!
 *  \file thresholdrulecomplex.h
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \brief Complex threshold rule representation
 */
#ifndef SRC_THRESHOLDRULECOMPLEX_H
#define SRC_THRESHOLDRULECOMPLEX_H

// used for zsys

#include <czmq.h>
#include "luarule.h"
extern "C" {
#include <lua.h>
}

class ThresholdRuleComplex : public LuaRule
{
public:

    ThresholdRuleComplex(){};

    int evaluate (const MetricList &metricList, PureAlert **pureAlert) const;
    bool isTopicInteresting(const std::string &topic) const ;
    std::set<std::string> getNeededTopics(void) const;
    friend Rule* readRule (std::istream &f);
protected:
    lua_State* setContext (const MetricList &metricList) const;

private:
    // needed metric topic
    std::set<std::string> _metrics;
};


#endif // SRC_THRESHOLDRULECOMPLEX_H
