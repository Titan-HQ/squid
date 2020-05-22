/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "auth/kshield/Config.h"
#include "auth/kshield/Scheme.h"
#include "Debug.h"
#include "helper.h"

Auth::Scheme::Pointer Auth::Kshield::Scheme::_instance = NULL;

Auth::Scheme::Pointer
Auth::Kshield::Scheme::GetInstance()
{
    if (_instance == NULL) {
        _instance = new Auth::Kshield::Scheme();
        AddScheme(_instance);
    }
    return _instance;
}

char const *
Auth::Kshield::Scheme::type() const
{
    return "kshield";
}

void
Auth::Kshield::Scheme::shutdownCleanup()
{
    if (_instance == NULL)
        return;

    _instance = NULL;
    debugs(29, DBG_CRITICAL, "Shutdown: Kshield authentication.");
}

Auth::Config *
Auth::Kshield::Scheme::createConfig()
{
    Auth::Kshield::Config *newCfg = new Auth::Kshield::Config;
    return dynamic_cast<Auth::Config*>(newCfg);
}

