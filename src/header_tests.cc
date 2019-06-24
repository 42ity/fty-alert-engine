/*  =========================================================================
    header_tests - Unit tests for all header types

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
    header_tests - Unit tests for all header types
@discuss
@end
*/

#include <string>

#include "fty_alert_engine_classes.h"

//  --------------------------------------------------------------------------
//  Self test of this class

// If your selftest reads SCMed fixture data, please keep it in
// src/selftest-ro; if your test creates filesystem objects, please
// do so under src/selftest-rw.
// The following pattern is suggested for C selftest code:
//    char *filename = NULL;
//    filename = zsys_sprintf ("%s/%s", SELFTEST_DIR_RO, "mytemplate.file");
//    assert (filename);
//    ... use the "filename" for I/O ...
//    zstr_free (&filename);
// This way the same "filename" variable can be reused for many subtests.
#define SELFTEST_DIR_RO "src/selftest-ro"
#define SELFTEST_DIR_RW "src/selftest-rw"

void
runDatabaseUT (bool verbose)
{
    //TODO: FIXME: add UT for Database, as they are tested by assetDatabase anyway, but not for all the uses we can do
}

void assetDatabaseUT1 () {
    BasicAsset ba1 ("id-1", "active", "device", "rackcontroller");
    BasicAsset ba2 ("id-2", "active", "device", "rackcontroller");
    BasicAsset ba3 ("id-3", "active", "device", "rackcontroller");
    BasicAsset ba4 ("id-4", "active", "device", "rackcontroller");
    ExtendedAsset ea1 ("id-5", "active", "device", "rackcontroller", "MyRack", "id-1", 1);
    ExtendedAsset ea2 ("id-6", "active", "device", "rackcontroller", "MyRack", "id-1", 1);
    ExtendedAsset ea3 ("id-7", "active", "device", "rackcontroller", "MyRack", "id-1", 1);
    ExtendedAsset ea4 ("id-8", "active", "device", "rackcontroller", "MyRack", "id-1", 1);
    FullAsset fa1 ("id-9", "active", "device", "rackcontroller", "MyRack", "id-1", 1, {{"aux1", "aval1"}},
            {{"ext1", "eval1"}});
    FullAsset fa2 ("id-10", "active", "device", "rackcontroller", "MyRack", "id-1", 1, {{"aux1", "aval1"}},
            {{"ext1", "eval1"}});
    FullAsset fa3 ("id-11", "active", "device", "rackcontroller", "MyRack", "id-1", 1, {{"aux1", "aval1"}},
            {{"ext1", "eval1"}});
    FullAsset fa4 ("id-12", "active", "device", "rackcontroller", "MyRack", "id-1", 1, {{"aux1", "aval1"}},
            {{"ext1", "eval1"}});
    std::shared_ptr<BasicAsset> bap4 = std::make_shared<BasicAsset> (ba4);
    std::shared_ptr<ExtendedAsset> eap4 = std::make_shared<ExtendedAsset> (ea4);
    std::shared_ptr<FullAsset> fap4 = std::make_shared<FullAsset> (fa4);
    BasicAssetDatabase::getInstance ().insertOrUpdateAsset (ba1);
    BasicAssetDatabase::getInstance ().insertOrUpdateAsset (ba2);
    BasicAssetDatabase::getInstance ().insertOrUpdateAsset (ba3);
    BasicAssetDatabase::getInstance ().insertOrUpdateAsset (bap4);
    auto b = BasicAssetDatabase::getInstance ().getAsset ("id-1");
    assert (b != nullptr);
    assert (b->getId () == "id-1");
    assert (b->getStatusString () == "active");
    assert (b->getTypeString () == "device");
    assert (b->getSubtypeString () == "rackcontroller");
    b = BasicAssetDatabase::getInstance ().getAsset ("id-4");
    assert (b != nullptr);
    assert (b->getId () == "id-4");
    assert (b->getStatusString () == "active");
    assert (b->getTypeString () == "device");
    assert (b->getSubtypeString () == "rackcontroller");
    try {
        b = BasicAssetDatabase::getInstance ().getAsset ("id-0");
        assert (false); // exception expected
    } catch (element_not_found &eerror) {
    }
    try {
        auto e = ExtendedAssetDatabase::getInstance ().getAsset ("id-1");
        assert (false); // exception expected
    } catch (element_not_found &eerror) {
    }
    try {
        auto f = FullAssetDatabase::getInstance ().getAsset ("id-1");
        assert (false); // exception expected
    } catch (element_not_found &eerror) {
    }
    ExtendedAssetDatabase::getInstance ().insertOrUpdateAsset (ea1);
    ExtendedAssetDatabase::getInstance ().insertOrUpdateAsset (ea2);
    ExtendedAssetDatabase::getInstance ().insertOrUpdateAsset (eap4);
    try {
        auto e = ExtendedAssetDatabase::getInstance ().getAsset ("id-5");
    } catch (element_not_found &eerror) {
        assert (false); // exception not expected
    }
    try {
        auto e = ExtendedAssetDatabase::getInstance ().getAsset ("id-8");
    } catch (element_not_found &eerror) {
        assert (false); // exception not expected
    }
    FullAssetDatabase::getInstance ().insertOrUpdateAsset (fa1);
    FullAssetDatabase::getInstance ().insertOrUpdateAsset (fa2);
    FullAssetDatabase::getInstance ().insertOrUpdateAsset (fap4);
    try {
        auto f = FullAssetDatabase::getInstance ().getAsset ("id-9");
    } catch (element_not_found &eerror) {
        assert (false); // exception not expected
    }
    try {
        auto f = FullAssetDatabase::getInstance ().getAsset ("id-12");
    } catch (element_not_found &eerror) {
        assert (false); // exception not expected
    }
    // mixing basic assets into extended and full asset DB is unsupported
    // ExtendedAssetDatabase::getInstance ().insertOrUpdateAsset (ba1);
    // ExtendedAssetDatabase::getInstance ().insertOrUpdateAsset (bap4);
    // FullAssetDatabase::getInstance ().insertOrUpdateAsset (ba1);
    // FullAssetDatabase::getInstance ().insertOrUpdateAsset (bap4);
    // while it's eligible the other way around
    BasicAssetDatabase::getInstance ().insertOrUpdateAsset (ea1);
    BasicAssetDatabase::getInstance ().insertOrUpdateAsset (eap4);
    BasicAssetDatabase::getInstance ().insertOrUpdateAsset (fa1);
    BasicAssetDatabase::getInstance ().insertOrUpdateAsset (fap4);
    ExtendedAssetDatabase::getInstance ().insertOrUpdateAsset (fa1);
    ExtendedAssetDatabase::getInstance ().insertOrUpdateAsset (fap4);
    try {
        b = BasicAssetDatabase::getInstance ().getAsset ("id-5");
    } catch (element_not_found &eerror) {
        assert (false); // exception not expected
    }
    try {
        b = BasicAssetDatabase::getInstance ().getAsset ("id-8");
    } catch (element_not_found &eerror) {
        assert (false); // exception not expected
    }
    // while it is OK to insert assets via value, make_shared strips them to base class so extended attributes are lost
    try {
        b = BasicAssetDatabase::getInstance ().getAsset ("id-9");
    } catch (element_not_found &eerror) {
        assert (false); // exception not expected
    }
    // but not when assets are passed as shared_ptrs
    try {
        b = BasicAssetDatabase::getInstance ().getAsset ("id-12");
    } catch (element_not_found &eerror) {
        assert (false); // exception not expected
    }
    try {
        auto f = std::dynamic_pointer_cast<FullAsset>(b);
        assert (f != nullptr);
        assert (f->getItem ("aux1") == "aval1");
    } catch (std::exception &e) {
        assert (false); // exception not expected
    }
    try {
        auto e = ExtendedAssetDatabase::getInstance ().getAsset ("id-9");
    } catch (element_not_found &eerror) {
        assert (false); // exception not expected
    }
    try {
        auto e = ExtendedAssetDatabase::getInstance ().getAsset ("id-12");
        auto f = std::dynamic_pointer_cast<FullAsset>(e);
        assert (f != nullptr);
        assert (f->getItem ("aux1") == "aval1");
    } catch (std::exception &e) {
        assert (false); // exception not expected
    }
    auto g = FullAssetDatabase::getInstance ().getAssetForManipulation ("id-10");
    assert (g->getAuxItem ("aux5") == "");
    g->setAuxItem ("aux5", "aval5");
    auto h = FullAssetDatabase::getInstance ().getAsset ("id-10");
    assert (h->getAuxItem ("aux5") == "aval5");
}

void assetDatabaseUT2 () {
    // access assets outside of previous function scope
    auto b = BasicAssetDatabase::getInstance ().getAsset ("id-1");
    assert (b != nullptr);
    assert (b->getId () == "id-1");
    assert (b->getStatusString () == "active");
    assert (b->getTypeString () == "device");
    assert (b->getSubtypeString () == "rackcontroller");
    b = BasicAssetDatabase::getInstance ().getAsset ("id-4");
    assert (b != nullptr);
    assert (b->getId () == "id-4");
    assert (b->getStatusString () == "active");
    assert (b->getTypeString () == "device");
    assert (b->getSubtypeString () == "rackcontroller");
    try {
        b = BasicAssetDatabase::getInstance ().getAsset ("id-0");
        assert (false); // exception expected
    } catch (element_not_found &eerror) {
    }
    try {
        auto e = ExtendedAssetDatabase::getInstance ().getAsset ("id-1");
        assert (false); // exception expected
    } catch (element_not_found &eerror) {
    }
    try {
        auto f = FullAssetDatabase::getInstance ().getAsset ("id-1");
        assert (false); // exception expected
    } catch (element_not_found &eerror) {
    }
    int count = 0;
    for (auto asset_it : FullAssetDatabase::getInstance ()) {
        assert (asset_it.first == "id-10" || asset_it.first == "id-12" || asset_it.first == "id-9");
        ++count;
    }
    assert (count == 3);
}

class AssetDatabaseUT3 {
    private:
        bool created_;
        bool updated_;
        bool deleted_;
    public:
        AssetDatabaseUT3 () : created_(false), updated_(false), deleted_(false) { }
        void externalFunctionInsert (const std::shared_ptr<FullAsset> a) {
            created_ = true;
            assert (a->getId () == "id-14");
        }
        void internalFunctionInsert (const std::shared_ptr<FullAsset> a) {
            created_ = true;
            assert (a->getId () == "id-15");
        }
        void internalTest () {
            created_ = false;
            updated_ = false;
            deleted_ = false;
            assert (created_ == false);
            FullAsset fa7 ("id-15", "active", "device", "rackcontroller", "MyRack", "id-1", 1, {{"aux15", "aval15"}},
                    {{"ext15", "eval15"}});
            FullAssetDatabase::getInstance ().setOnCreate (std::bind (&AssetDatabaseUT3::internalFunctionInsert, this,
                    std::placeholders::_1));
            FullAssetDatabase::getInstance ().insertOrUpdateAsset (fa7);
            assert (created_ == true);
        }
        bool getCreated () { return created_; }
};

void assetDatabaseUT3 () {
    bool created = false;
    bool updated = false;
    bool deleted = false;
    FullAssetDatabase::getInstance ().setOnCreate ([&](const std::shared_ptr<FullAsset> a){
            assert (a->getId () == "id-13"); created=true; });
    FullAssetDatabase::getInstance ().setOnUpdate ([&](const std::shared_ptr<FullAsset> a){
            assert (a->getId () == "id-13"); updated=true; });
    FullAssetDatabase::getInstance ().setOnDelete ([&](const std::shared_ptr<FullAsset> a){
            assert (a->getId () == "id-13"); deleted=true; });
    FullAsset fa5 ("id-13", "active", "device", "rackcontroller", "MyRack", "id-1", 1, {{"aux13", "aval13"}},
            {{"ext13", "eval13"}});
    assert (created == false);
    assert (updated == false);
    assert (deleted == false);
    FullAssetDatabase::getInstance ().insertOrUpdateAsset (fa5);
    assert (created == true);
    assert (updated == false);
    assert (deleted == false);
    FullAssetDatabase::getInstance ().insertOrUpdateAsset (fa5);
    assert (created == true);
    assert (updated == true);
    assert (deleted == false);
    AssetDatabaseUT3 adut3;
    assert (adut3.getCreated () == false);
    FullAsset fa6 ("id-14", "active", "device", "rackcontroller", "MyRack", "id-1", 1, {{"aux14", "aval14"}},
            {{"ext14", "eval14"}});
    FullAssetDatabase::getInstance ().setOnCreate (std::bind (&AssetDatabaseUT3::externalFunctionInsert, &adut3, std::placeholders::_1));
    FullAssetDatabase::getInstance ().insertOrUpdateAsset (fa6);
    assert (adut3.getCreated () == true);
    adut3.internalTest ();
}
void
runAssetDatabaseUT (bool verbose)
{
    BasicAssetDatabase::getInstance ().clear ();
    ExtendedAssetDatabase::getInstance ().clear ();
    FullAssetDatabase::getInstance ().clear ();
    // basic tests
    assetDatabaseUT1 ();
    // test content from different function context
    assetDatabaseUT2 ();
    // test hooks
    assetDatabaseUT3 ();
}

void
runRuleFactoryUT (bool verbose)
{
    // flexible rule sts-voltage@device_sts.rule
    std::string json1 = std::string ("{ \"flexible\" : { \"name\" : \"sts-voltage@__name__\", \"description\" : \"") +
            "TRANSLATE_LUA (The STS/ATS voltage is out of tolerance)\", \"categories\" : [\"CAT_OTHER\", \"CAT_ALL\"]" +
            ", \"metrics\" : [\"status.input.1.voltage\", \"status.input.2.voltage\"], \"assets\" : [\"__name__\"" +
            "], \"results\" : [ { \"high_warning\" : { \"action\" : [ ], \"severity\" : \"WARNING\", \"description\" " +
            ": \"none\" } } ], \"evaluation\" : \" function main (i1," + " i2) if i1 == 'good' and i2 == 'good' then return OK, string.format ('{ \\\"key\\\": \\\"TRANSLATE_LUA (" + "Voltage status of both inputs of {{NAME}} is good.)\\\", \\\"variables\\\": {\\\"NAME\\\": \\\"NAME\\\"" + "}}') end if i1 == 'good' then return WARNING, string.format ('{ \\\"key\\\": \\\"TRANSLATE_LUA (Input 2 " + "voltage status of {{NAME}} is out of tolerance ({{i2}})!)\\\", \\\"variables\\\": {\\\"NAME\\\": \\\"" + "NAME\\\", \\\"i2\\\" : \\\"%s\\\"}}', i2) end if i2 == 'good' then return WARNING, string.format ('{ " + "\\\"key\\\": \\\"TRANSLATE_LUA (Input 1 voltage status of {{NAME}} is out of tolerance ({{i1}})!)\\\", " + "\\\"variables\\\": {\\\"NAME\\\": \\\"NAME\\\", \\\"i1\\\" : \\\"%s\\\"}}', i1) end return WARNING, " + "string.format ('{ \\\"key\\\": \\\"TRANSLATE_LUA (Voltage status of both inputs is out of tolerance " + "({{i1}}, {{i2}})!)\\\", \\\"variables\\\": {\\\"i2\\\": \\\"%s\\\", \\\"i1\\\" : \\\"%s\\\"}}', i2, i1) " + "end \" } }";
    auto rule = RuleFactory::createFromJson (json1);
    assert (rule->whoami () == "flexible");
    assert (rule->getName () == "sts-voltage@__name__");
}

void
header_tests_test (bool verbose)
{
    printf (" * header_tests:\n");

    printf (" * * testing database class : ");
    runDatabaseUT (verbose);
    printf ("OK\n");

    printf (" * * testing asset database class : ");
    runAssetDatabaseUT (verbose);
    printf ("OK\n");

    printf (" * * testing rule factory class : ");
    runRuleFactoryUT (verbose);
    printf ("OK\n");

    printf (" * header_tests: OK\n");
}
