#include <iostream>
#include <limits>

#include <stdio.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>

#include <poppler/GlobalParams.h>
#include <poppler/Gfx.h>
#include <poppler/Page.h>
#include <poppler/PDFDoc.h>
#include <poppler/DateInfo.h>
#include <poppler/UnicodeMap.h>
#include <poppler/UTF.h>
#include <poppler/TextOutputDev.h>
#include <poppler/goo/GooList.h>
#include <poppler/goo/gfile.h>
#include <poppler/goo/GooString.h>

#include <msgpack.hpp>

#include "util.hpp"

#include "DumpAsMsgPackDev.h"
#include "DumpAsTextDev.h"
#include "NopDev.h"

msgpack::packer<std::ostream> packer(&std::cout);

#include "seccomp-bpf.h"
#include "syscall-reporter.h"

static int install_syscall_filter(void)
{
	struct sock_filter filter[] = {
		/* Validate architecture. */
		VALIDATE_ARCHITECTURE,
		/* Grab the system call number. */
		EXAMINE_SYSCALL,
		/* List allowed syscalls. */
		ALLOW_SYSCALL(open),
		ALLOW_SYSCALL(close),
		ALLOW_SYSCALL(read),
		ALLOW_SYSCALL(pread64),
		ALLOW_SYSCALL(futex),
		ALLOW_SYSCALL(time),
		ALLOW_SYSCALL(gettimeofday),
		ALLOW_SYSCALL(fstat),
		ALLOW_SYSCALL(mmap),
		ALLOW_SYSCALL(munmap),
		ALLOW_SYSCALL(lseek),
		ALLOW_SYSCALL(write),
		ALLOW_SYSCALL(brk),
		ALLOW_SYSCALL(exit),
		ALLOW_SYSCALL(exit_group),
		KILL_PROCESS,
	};
	install_syscall_reporter();

	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl(NO_NEW_PRIVS)");
		exit(99);
	}
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		perror("prctl(SECCOMP)");
		exit(99);
	}
	return 0;
}


static std::string fmt(Object *o, UnicodeMap *uMap) {
	if (!o)
	return "<nil>";
	if (!o->isString())
	return "<not string>";

	auto s = o->getString();

	char buf[9];
	Unicode *u;
	auto len = TextStringToUCS4(s, &u);

	std::string out;
	out.reserve(static_cast<size_t>(len));

	for (auto i = 0; i < len; i++) {
		auto n = uMap->mapUnicode(u[i], buf, sizeof(buf));
		out.append(buf, n);
	}

	return out;
}

void dump_document_meta(PDFDoc *doc, UnicodeMap *uMap) {

	// TODO(pwaller):
	// * Decide what it's useful to dump here.
	// * Dump it in msgpack format.

	printf("Pages:	  %d\n", doc->getNumPages());
	printf("PDF version:	%d.%d\n", doc->getPDFMajorVersion(), doc->getPDFMinorVersion());

	Object info;
	doc->getDocInfo(&info);
	auto dict = info.getDict();

	printf("Keys: ");
	for (int i = 0; i < dict->getLength(); i++) {
		printf("%s, ", dict->getKey(i));
	}
	printf("\n");

	if (info.isDict()) {
		auto dict = info.getDict();
		Object o;
		std::cout << "Creator: " << fmt(dict->lookup("Creator", &o), uMap) << std::endl;

		// printInfoString(dict, "Creator",	  "Creator:	", uMap);
		// printInfoString(dict, "Producer",	 "Producer:	   ", uMap);
		// printInfoString(dict, "CreationDate", "CreationDate:   ", uMap);
		// printInfoString(dict, "ModDate",	  "ModDate:	", uMap);
	}
}

TextPage* page_to_text_page(Page *page) {

	// TODO(pwaller):
	// * Deal with rotated pages (multiples of 90 degrees).
	// * Deal with rotated text (arbitrarily rotated).

	auto dev = new TextOutputDev(NULL, gTrue, 0, gFalse, gFalse);

	auto gfx = page->createGfx(
		dev,
		72.0, 72.0, 0,
		gFalse, /* useMediaBox */
		gTrue, /* Crop */
		-1, -1, -1, -1,
		gFalse, /* printing */
		NULL, NULL
	);

	page->display(gfx);
	dev->endPage();

	auto text = dev->takeText();

	delete gfx;
	delete dev;

	return text;
}

int count_glyphs(GooList **lines, int n_lines) {
	int total_glyphs = 0;

	for (int i = 0; i < n_lines; i++) {
		auto *words = lines[i];
		total_glyphs += words->getLength() - 1; // spaces
		for (int j = 0; j < words->getLength(); j++) {
			auto *x = reinterpret_cast<TextWordSelection *>(words->get(j));
			auto *word = reinterpret_cast<TextWord*>(x->getWord());
			total_glyphs += word->getLength();
		}
	}
	return total_glyphs;
}

void dump_glyphs(GooList **lines, int n_lines) {
	// Lines
	for (int i = 0; i < n_lines; i++) {
		GooList *line_words = lines[i];

		// Words
		for (int j = 0; j < line_words->getLength(); j++) {
			auto word_sel = reinterpret_cast<TextWordSelection*>(line_words->get(j));
			TextWord *word = word_sel->getWord();

			// Glyphs
			for (int k = 0; k < word->getLength(); k++) {
				double x1, y1, x2, y2;
				word->getCharBBox(k, &x1, &y1, &x2, &y2);

				auto rect = std::make_tuple(x1, y1, x2, y2);
				packer.pack(std::make_tuple(rect, toUTF8(word, k)));
			}

			double x1, y1, x2, y2;
			double x3, y3, x4, y4;
			word->getBBox (&x1, &y1, &x2, &y2);

			// Spaces
			if (j < line_words->getLength() - 1) {
				auto word_sel = reinterpret_cast<TextWordSelection*>(line_words->get(j + 1));
				word_sel->getWord()->getBBox(&x3, &y3, &x4, &y4);
				// space is from one word to other and with the same height as
				// first word.
				
				x1 = x2;
				// y1 = y1; (implicit)
				x2 = x3;
				// y2 = y2; (implicit)

				auto rect = std::make_tuple(x1, y1, x2, y2);
				packer.pack(std::make_tuple(rect, " "));
			}
		}
	}
}

void free_word_list(GooList **lines, int n_lines) {
	for (int i = 0; i < n_lines; i++) {
		deleteGooList(lines[i], TextWordSelection);
	}
	gfree(lines);
}

void dump_page(Page *page) {
	auto text = page_to_text_page(page);

	const auto inf = std::numeric_limits<double>::infinity();

	PDFRectangle whole_page(-inf, -inf, inf, inf);

	int n_lines;
	auto word_list = text->getSelectionWords(&whole_page, selectionStyleGlyph, &n_lines);

	int total_glyphs = count_glyphs(word_list, n_lines);

	packer.pack_array(total_glyphs);
	dump_glyphs(word_list, n_lines);

	free_word_list(word_list, n_lines);
	text->decRefCnt();
}

void dump_page_nop(Page *page) {
	auto dev = new NopDev();

	auto gfx = page->createGfx(
		dev,
		72.0, 72.0, 0,
		gFalse, /* useMediaBox */
		gTrue, /* Crop */
		-1, -1, -1, -1,
		gFalse, /* printing */
		NULL, NULL
	);

	page->display(gfx);

	delete gfx;
	delete dev;
}

void dump_document(PDFDoc *doc) {
	int n_pages = doc->getNumPages();

	packer.pack_array(n_pages);

	// Pages are one-based in this API. Beware, 0 based elsewhere.
	for (int i = 1; i < n_pages+1; i++) {
		dump_page(doc->getPage(i));
		// dump_page_nop(doc->getPage(i));
	}
}

BaseStream* open_file(const char *filename) {
	GooString goo_filename(filename);
	auto file = GooFile::open(&goo_filename);
	if (file == NULL) {
		std::cerr << "Failed to open " << filename << std::endl;
		exit(5);
	}

	Object obj;
	obj.initNull();
	return new FileStream(file, 0, gFalse, file->size(), &obj);
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		std::cerr << "usage: pdf2msgpack <filename>" << std::endl;
		return 1;
	}

	auto file = open_file(argv[1]);


	if (!globalParams) {
		globalParams = new GlobalParams("/usr/share/poppler");
	}

	install_syscall_filter();
	UnicodeMap *uMap;
	if (!(uMap = globalParams->getTextEncoding())) {
		return 127;
	}


	auto doc = new PDFDoc(file);
	// auto doc = new PDFDoc(new GooString(argv[1]));
	if (!doc) {
		std::cerr << "Problem loading document." << std::endl;
		return 64;
	}

	if (!doc->isOk()) {
		std::cerr << "Failed to open: " << doc->getErrorCode() << std::endl;
		return 63;
	}

	// dump_document_meta(doc, uMap);
	dump_document(doc);

	delete doc;
}
