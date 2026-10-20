/* rfg_codegen.py: pcrecomp lift32, PDB extents, units of whole source files. DO NOT EDIT. */
#define RECOMP_GENERATED_CODE
#include "recomp_types.h"
#include "recomp_funcs.h"
#include <math.h>
#include <string.h>

#include "rfg_names.h"
#include "../src/havok_20150629/common/internal/geometryprocessing/hkgeometryprocessing.inl.c"
#include "../src/havok_20150629/common/base/types/geometry/sphere/hksphere.inl.c"
#include "../src/havok_20150629/common/internal/geometryprocessing/convexhull/hkgpconvexhull.h.c"
#include "../src/havok_20150629/common/internal/geometryprocessing/abstractmesh/hkgpabstractmesh.inl.c"
#include "../src/havok_20150629/common/internal/geometryprocessing/hkgeometryprocessing.cpp.c"
#include "../src/havok_20150629/common/internal/math/hkvector4utilinternal.inl.c"
#include "../src/havok_20150629/geometry/internal/algorithms/distance/hkcddistancepointline.inl.c"
#include "../src/havok_20150629/common/internal/geometryprocessing/indexedmesh/hkgpindexedmesh.h.c"
#include "../src/havok_20150629/common/base/container/tree/hksortedtree.h.c"
#include "../src/havok_20150629/common/base/container/tree/hksortedtree.inl.c"
#include "../src/havok_20150629/geometry/internal/datastructures/dynamictree/hkcddynamictree.h.c"
#include "../src/havok_20150629/geometry/internal/datastructures/dynamictree/hkcddynamictreecodecs.h.c"
#include "../src/havok_20150629/geometry/internal/algorithms/treequeries/hkcdtreequeriesinternals.inl.c"
