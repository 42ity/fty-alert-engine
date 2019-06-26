/*  =========================================================================
    rule-checker - Check rules for errors

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

/*
@header
    rule-checker - Check rules for errors
@discuss
@end
*/

#include <iostream>
#include <string>
#include <vector>
#include <utility>
#include <cxxtools/directory.h>
#include <fstream>

#include "fty_alert_engine_classes.h"

std::vector<std::pair<std::string, std::string>> getAllTemplatesMap (const std::string &path) {
    log_debug ("Getting all rules");
    std::vector<std::pair<std::string, std::string>> result;
    if (!cxxtools::Directory::exists (path)) {
        log_info ("TemplateRuleConfigurator '%s' dir does not exist", path.c_str ());
        return result;
    }
    cxxtools::Directory directory (path);
    for ( const auto &filename : directory) {
        if ( filename.compare (".") != 0  && filename.compare ("..") != 0 && filename.compare (
                filename.length () - std::strlen (".rule"), std::string::npos, ".rule") ==0 ) {
            try {
                // read the rule from the file
                std::ifstream file (directory.path () + "/" + filename);
                std::string file_content ((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                std::shared_ptr<Rule> rule = RuleFactory::createFromJson (file_content);
                result.push_back (std::make_pair (filename, "valid"));
            } catch (std::exception &e)
            {
                std::cerr << filename << ": " <<  e.what() << std::endl;
                result.push_back (std::make_pair (filename, "invalid"));
            }
        }
    }
    return result;
}

int main (int argc, char *argv [])
{
    bool verbose = false;
    int argn;
    for (argn = 1; argn < argc; argn++) {
        if (streq (argv [argn], "--help")
        ||  streq (argv [argn], "-h")) {
            puts ("rule-checker [options] ...");
            puts ("  --verbose / -v         verbose test output");
            puts ("  --directory / -d       check all .rule files in directory");
            puts ("  --help / -h            this information");
            return 0;
        }
        else if (streq (argv [argn], "-d") || streq (argv [argn], "--directory")) {
            std::string path (argv[++argn]);
            std::vector<std::pair<std::string, std::string>> results = getAllTemplatesMap (path);
            std::cout << "Checked directory: " << path << std::endl;
            std::cout << "Result:" << std::endl;
            
            int errors = 0;

            for (auto &p : results) {
                if(p.second == "invalid")
                {
                    errors++;
                    std::cout << "\033[31m" << p.first << " : " << p.second << "\033[0m" << std::endl;
                }
                else
                {
                    std::cout << "\033[32m" << p.first << " : " << p.second << "\033[0m" << std::endl;
                    
                }
                
            }

            return errors;
        }
        else
        if (streq (argv [argn], "--verbose")
        ||  streq (argv [argn], "-v"))
            verbose = true;
        else {
            printf ("Unknown option: %s\n", argv [argn]);
            return 1;
        }
    }
    //  Insert main code here
    if (verbose)
        zsys_info ("rule-checker - Check rules for errors");
    return 0;
}
