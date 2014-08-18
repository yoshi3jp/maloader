# Makefile 3

# マクロ定義部
CC      = clang
CUIOBJS = main.o bind.o
BASEOBJS    =
DEP	= -ldl
IOS	    = -arch armv7 -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS6.1.sdk


# 生成規則部

main: $(CUIOBJS) $(BASEOBJS)
	$(CC) -rdynamic -I$(CURDIR) -o $@ $^ $(DEP)

ios-main: $(CUIOBJS) $(BASEOBJS)
	$(CC) -rdynamic -I$(CURDIR) -o $@ $^ $(DEP)

.c.o:
	$(CC) -I$(CURDIR) -c $< $(DEP)


######
clean: 
	@rm -rf *.dSYM *.o
