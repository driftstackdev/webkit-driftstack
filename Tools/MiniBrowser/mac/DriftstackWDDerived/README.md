# DriftstackWDDerived — item-9 generated WebDriver atoms

`WebDriverAtoms.{h,cpp}` are GENERATED (not hand-written): the CMake WebDriver build produces them
from the 8 automation atoms in `Source/WebKit/UIProcess/Automation/atoms/*.js`, but the Xcode
MiniBrowser target has no such build step, so they're generated here and committed. Session.cpp
`#include "WebDriverAtoms.h"`; the .cpp provides the JS atom byte-arrays.

Regenerate (from webkit-driftstack root) if the atoms change:
  D=Tools/MiniBrowser/mac/DriftstackWDDerived; A=Source/WebKit/UIProcess/Automation/atoms
  for a in ElementAttribute ElementDisplayed ElementEnabled ElementText EnterFullscreen FindNodes FormElementClear FormSubmit; do \
    python3 Source/WebKit/Scripts/generate-automation-atom.py $A/$a.js $D/$a.js; done
  python3 Source/JavaScriptCore/Scripts/make-js-file-arrays.py -n WebDriver $D/WebDriverAtoms.h $D/WebDriverAtoms.cpp $D/*.js && rm $D/Element*.js $D/Enter*.js $D/Find*.js $D/Form*.js
