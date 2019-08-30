
ifndef ldscript
$(error Set 'ldscript' to the linker script to use, eg, "make ldscript=ldscript.d3d10")
endif

CC = x86_64-w64-mingw32-gcc
FLAGS =  -mdll -s -T $(ldscript) -lws2_32

all : hello.dll globalCstrs.dll winsock.dll tls.dll
clean : hello.dll-clean globalCstrs.dll-clean winsock.dll-clean tls.dll-clean

%.dll :
	$(CC) $(basename $@).cpp -o $@ $(FLAGS) 

%.dll-clean :
	rm $(basename $@).dll
