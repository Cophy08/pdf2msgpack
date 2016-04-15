#include <poppler/OutputDev.h>
#include <poppler/GfxState.h>
#include <poppler/GfxFont.h>

class NopDev : public OutputDev {
public:

  NopDev() {}

public:

  GBool upsideDown() { return gFalse; }
  GBool useDrawChar() { return gTrue; }
  GBool interpretType3Chars() { return gTrue; }

  virtual void drawSoftMaskedImage(GfxState*, Object*, Stream*, int, int, GfxImageColorMap*, bool, Stream*, int, int, GfxImageColorMap*, bool) {}
};
