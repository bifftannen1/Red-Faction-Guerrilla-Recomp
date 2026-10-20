/* rfg_codegen.py: pcrecomp lift32, PDB extents, units of whole source files. DO NOT EDIT. */
#define RECOMP_GENERATED_CODE
#include "recomp_types.h"
#include "recomp_funcs.h"
#include <math.h>
#include <string.h>

#include "rfg_names.h"
#include "../src/rfg/volition/libmodules/havok/hk2014_2_5_r1/source/physics/constraint/data/ragdoll/hkpragdollconstraintdata.inl.c"
#include "../src/rfg/volition/libmodules/havok/hk2014_2_5_r1/source/physics2012/dynamics/constraint/breakable/hkpbreakableconstraintdata.inl.c"
#include "../src/rfg/volition/libmodules/havok/hk2014_2_5_r1/source/physics/constraint/data/limitedhinge/hkplimitedhingeconstraintdata.inl.c"
#include "../src/rfg/volition/libmodules/havok/hk2014_2_5_r1/source/physics2012/collide/shape/heightfield/trisampledheightfield/hkptrisampledheightfieldbvtreeshape.inl.c"
#include "../src/rfg/volition/libmodules/havok/hk2014_2_5_r1/source/physics2012/collide/shape/compound/tree/mopp/hkpmoppbvtreeshape.inl.c"
#include "../src/rfg/volition/libmodules/havok/hk2014_2_5_r1/source/physics/constraint/motor/limitedforce/hkplimitedforceconstraintmotor.h.c"
#include "../src/rfg/volition/libmodules/havok/hk2014_2_5_r1/source/physics2012/collide/query/collector/bodypaircollector/hkpallcdbodypaircollector.inl.c"
#include "../src/rfg/volition/libmodules/havok/hk2014_2_5_r1/source/common/base/memory/allocator/freelist/hkfreelistallocator.h.c"
#include "../src/rfg/volition/libmodules/havok/hk2014_2_5_r1/source/physics/constraint/data/pointtopath/hkppointtopathconstraintdata.inl.c"
#include "../src/rfg/volition/libmodules/havok/hk2014_2_5_r1/source/physics2012/collide/dispatch/hkpcollisiondispatcher.inl.c"
#include "../src/rfg/volition/rfg/code/havok/havok.cpp.c"
#include "../src/rfg/volition/rfg/code/havok/havok_bp.cpp.c"
#include "../src/rfg/volition/libmodules/havok/hk2014_2_5_r1/source/common/serialize/util/hkbuiltintyperegistry.h.c"
#include "../src/rfg/volition/libmodules/havok/hk2014_2_5_r1/source/common/base/reflection/hktypeinfo.h.c"
#include "../src/rfg/volition/libmodules/havok/hk2014_2_5_r1/source/common/base/types/geometry/hkstridedvertices.h.c"
#include "../src/rfg/volition/rfg/code/havok/havok_cm_manager.cpp.c"
#include "../src/rfg/volition/rfg/code/havok/havok_collision_callbacks.cpp.c"
#include "../src/rfg/volition/rfg/code/havok/havok_collision_events.cpp.c"
#include "../src/rfg/volition/rfg/code/havok/havok_collision_immediate_callbacks.cpp.c"
#include "../src/rfg/volition/rfg/code/havok/havok_convert.cpp.c"
