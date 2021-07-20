#include "CADD.h"
#include "CMUL.h"

namespace certFHE {

	void CMUL::upstream_merging() {


	}

	CNODE * CMUL::make_copy() {

		return new CMUL(*this);
	}

	CNODE * CMUL::upstream_merging(CNODE * fst, CNODE * snd) {

		CCC * fst_c = dynamic_cast<CCC *>(fst);
		if (fst_c != 0) {

			CCC * snd_c = dynamic_cast<CCC *>(fst);
			if (snd_c != 0)
				return CMUL::upstream_merging((CCC *)fst_c, (CCC *)snd_c);

			else {

				CADD * snd_c = dynamic_cast<CADD *>(fst);
				if (snd_c != 0)
					return CMUL::upstream_merging((CADD *)snd_c, (CCC *)fst_c);


				else {

					CMUL * snd_c = dynamic_cast<CMUL *>(fst);
					return CMUL::upstream_merging((CMUL *)snd_c, (CCC *)fst_c);
				}
			}
		}
		else {

			CADD * fst_c = dynamic_cast<CADD *>(fst);
			if (fst_c != 0) {

				CCC * snd_c = dynamic_cast<CCC *>(fst);
				if (snd_c != 0)
					return CMUL::upstream_merging((CADD *)fst_c, (CCC *)snd_c);

				else {

					CADD * snd_c = dynamic_cast<CADD *>(fst);
					if (snd_c != 0)
						return CMUL::upstream_merging((CADD *)fst_c, (CADD *)snd_c);


					else {

						CMUL * snd_c = dynamic_cast<CMUL *>(fst);
						return CMUL::upstream_merging((CADD *)fst_c, (CMUL *)snd_c);
					}
				}
			}
			else {

				CMUL * fst_c = dynamic_cast<CMUL *>(fst);
				CCC * snd_c = dynamic_cast<CCC *>(fst);
				if (snd_c != 0)
					return CMUL::upstream_merging((CMUL *)fst_c, (CCC *)snd_c);

				else {

					CADD * snd_c = dynamic_cast<CADD *>(fst);
					if (snd_c != 0)
						return CMUL::upstream_merging((CADD *)snd_c, (CMUL *)fst_c);


					else {

						CMUL * snd_c = dynamic_cast<CMUL *>(fst);
						return CMUL::upstream_merging((CMUL *)fst_c, (CMUL *)snd_c);
					}
				}
			}
		}
	}

	CNODE * CMUL::__upstream_merging(CADD * fst, CADD * snd) { return 0; }
	CNODE * CMUL::__upstream_merging(CADD * fst, CMUL * snd) { return 0; }
	CNODE * CMUL::__upstream_merging(CMUL * fst, CMUL * snd) { return 0; }

	CNODE * CMUL::__upstream_merging(CADD * fst, CCC * snd) { return 0; }
	CNODE * CMUL::__upstream_merging(CCC * fst, CCC * snd) { return 0; }
	CNODE * CMUL::__upstream_merging(CMUL * fst, CCC * snd) { return 0; }
}


