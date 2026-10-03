#ifndef PCH_H
#define PCH_H

#include <string>
#include <iostream>

#include "framework.h"

using namespace std;

/*=========================================================================
Archetype - Version Selection
=========================================================================
Uncomment ONE version define, or use AUTO_VERSION for auto-detection.
AUTO_VERSION matches the EXE's entry point RVA against all known versions.

Supported versions: 21.20, 21.30, 21.40, 21.50, 21.51, 22.00, 22.10, 22.20
=========================================================================*/

#define V21_20 false // under tests
#define V21_30 false
#define V21_40 false // works
#define V21_50 true // under test/being worked on
#define V21_51 false
#define V22_00 false
#define V22_10 false
#define V22_20 false // works but scuffed
#define AUTO_VERSION false // Expermentall

#endif //PCH_H
