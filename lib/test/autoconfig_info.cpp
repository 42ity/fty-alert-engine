/*
Copyright (C) 2014 - 2020 Eaton

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

#include <catch2/catch.hpp>

#include "src/autoconfig_info.h"

TEST_CASE("autoconfig_info")
{
    // default & safe
    {
        AutoConfigurationInfo aci;

        CHECK(aci.type.empty());
        CHECK(aci.subtype.empty());
        CHECK(aci.update_ts.empty());
        CHECK(aci.date == 0);
        CHECK(aci.configured == false);
        CHECK(aci.attributes.empty());
        CHECK(aci.locations.empty());

        CHECK(aci.empty());
        CHECK(aci.getAttr("fake").empty());
        CHECK(aci.getAttr("fake", "def") == "def");
        CHECK(!aci.dump().empty());
        CHECK(!aci.dump({"fake"}).empty());
    }

    // empty()
    {
        AutoConfigurationInfo aci;

        aci.type = "";
        aci.subtype = "";
        CHECK(aci.empty());

        aci.type = "a";
        aci.subtype = "";
        CHECK(!aci.empty());

        aci.type = "";
        aci.subtype = "b";
        CHECK(aci.empty());

        aci.type = "a";
        aci.subtype = "b";
        CHECK(!aci.empty());
    }

    // operator == fty_proto_t
    {
        zmsg_t* msg = fty_proto_encode_asset(NULL, "name", "operation", NULL);
        fty_proto_t* proto = fty_proto_decode(&msg);
        REQUIRE(proto);

        AutoConfigurationInfo aci;

        // empty type/subtype/ext
        CHECK(aci == proto);

        // type/subtype
        aci.type = "device";
        aci.subtype = "ups";
        CHECK(!(aci == proto));
        fty_proto_aux_insert(proto, "type", "device");
        CHECK(!(aci == proto));
        fty_proto_aux_insert(proto, "subtype", "ups");
        CHECK(aci == proto);

        // ext. attributes
        aci.attributes["key0"] = "val0";
        aci.attributes["key1"] = "val1";
        CHECK(!(aci == proto));
        fty_proto_ext_insert(proto, "key0", "val0");
        CHECK(!(aci == proto));
        fty_proto_ext_insert(proto, "key1", "val1");
        CHECK(aci == proto);
        fty_proto_ext_insert(proto, "key1", "val2");
        CHECK(!(aci == proto));

        fty_proto_destroy(&proto);
    }

    // dump & ext. attributes
    {
        AutoConfigurationInfo aci;
        aci.attributes["key0"] = "val0";
        aci.attributes["key1"] = "val1";

        auto s0 = aci.dump();
        auto s1 = aci.dump({"key0"});
        auto s2 = aci.dump({"key1"});
        auto s3 = aci.dump({"key2"});
        CHECK(s0 != s1);
        CHECK(s1 != s2);
        CHECK(s2 != s3);
        CHECK(s3 != s0);
    }
}
