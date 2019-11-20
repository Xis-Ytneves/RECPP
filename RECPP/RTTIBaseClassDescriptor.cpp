﻿/*
    ██████╗ ███████╗ ██████╗██████╗ ██████╗ 
    ██╔══██╗██╔════╝██╔════╝██╔══██╗██╔══██╗
    ██████╔╝█████╗  ██║     ██████╔╝██████╔╝
    ██╔══██╗██╔══╝  ██║     ██╔═══╝ ██╔═══╝ 
    ██║  ██║███████╗╚██████╗██║     ██║     
    ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝     ╚═╝     
* @license : <license placeholder>
*/
#include "RTTIBaseClassDescriptor.h"
#include "TypeDescriptor.h"
#include "IDAUtils.h"


char *
CRTTIBaseClassDescriptor::parse (
    ea_t address,
    char *buffer3,
    size_t bufferSize
) {
    if (address == BADADDR || !address) {
        return NULL;
    }
    
    char buffer[2048] = {0};
    char buffer2[2048] = {0};
    char m1[2048] = {0};
    char m2[2048] = {0};
    char m3[2048] = {0};
    char m4[2048] = {0};

    IDAUtils::OffCmt(address, "pTypeDescriptor");
    IDAUtils::DwordCmt(address + 4, "numContainedBases");
    IDAUtils::DwordArrayCmt(address + 8, 3, "PMD where");
    IDAUtils::DwordCmt(address + 20, "attributes");

    char *s = CTypeDescriptor::parse (get_dword (address), buffer3, bufferSize);
    //??_R1A@?0A@A@B@@8 = B::`RTTI Base Class Descriptor at (0,-1,0,0)'
    IDAUtils::MangleNumber (get_dword (address + 8), m1, sizeof (m1));
    IDAUtils::MangleNumber (get_dword (address + 12), m2, sizeof (m2));
    IDAUtils::MangleNumber (get_dword (address + 16), m3, sizeof (m3));
    IDAUtils::MangleNumber (get_dword (address + 20), m4, sizeof (m4));

    sprintf_s (buffer, sizeof (buffer), "??_R1%s%s%s%s%s8", m1, m2, m3, m4, &s[4]);
    IDAUtils::MakeName (address, buffer);

    return s;
}
