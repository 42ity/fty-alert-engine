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
#include <cxxtools/jsondeserializer.h>
#include "luarule.h"
extern "C" {
#include <lua.h>
}

class ThresholdRuleComplex : public LuaRule
{
public:

    ThresholdRuleComplex(){};
    /*
     * \brief parse json and check lua and fill the object
     *
     * ATTENTION: throws, if bad JSON
     *
     * \return 1 if rule has other type
     *         2 if lua function has errors
     *         0 if everything is ok
     */
    int fill(cxxtools::JsonDeserializer &json, const std::string &json_string);

    friend int readRule (std::istream &f, Rule **rule);
};


#endif // SRC_THRESHOLDRULECOMPLEX_H
