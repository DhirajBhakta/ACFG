
 Next Generation Virus Construktion Kit
 by SnakeByte ( SnakeByte@kryptocrew.de )
 [ www.kryptocrew.de/snakebyte ]



0.) Important Information
1.) What is this ?
2.) Features
3.) Thanx & Greetz
4.) ToDo
5.) Thoughts and Ideas ( better skip this =) 







0.) Important Information

 This software is NOT written to create damage, therefore you will never see any destructive
 payload or something similar. Please do not abuse it, because virus spreading is illegal
 and you can get into serious problems by doing this. This construction kit is just
 meant to show what is possible nowadays and not to support kids, which want to
 infect one of their friends as a joke with a virus. Hope you keep this in mind
 while using.

 This program is still in its beta state, keep this in mind please. This
 does also mean, I am happy about every bug report. If you know, why there is a 
 problem, then please send in the code with a few comments in the lines with the
 error ( mark them in a way i find em quickly please ). If you are unexperienced
 with assembly language, please send in the Report of the SEH, and the version
 of your operating system ( Win95, 98, NT, ME, 2k .. ). 
 Thanks !
 
 


1.) What does this thingie do ?

 The Next Generation Virus Construktion Kit ( NGVCK ), or Construktor.Win32.NGVCK
 as AVP calls it, generates Win32 PE Infectors.
 All created viruses are completely different in structure and opcode.
 This makes it impossible to catch all variants with one or more scanstrings.
 First, the Kit generates the opcode form of the different modules.
 For example the Delta Offset routine might have one of the following appearances :

  --- Basic Version
   E800000000     call Delta
   5D             Delta: pop ebp
   81ED05104000   sub ebp, offset Delta
  --- E8000000005D81ED05104000
 
  --- Example 1 ( Different Instructions )
   E800000000      call Delta
   812C2405104000  Delta: sub dword ptr [esp], offset Delta
   58              pop eax
   8BE8            mov ebp, eax
  --- E800000000812C2405104000588BE8

  --- Example 2 ( Different Instructions + Trash )
   81C11B753100    add    ecx,0031751B   ; trash
   E800000000     call   Delta
   812C240B104000 Delta: sub dword ptr [esp], offset Delta
   81EB09090000    sub    ebx,00000909   ; trash
   8B1424         mov    edx,[esp]
   91              xchg   ecx,eax        ; trash
   83C404         add    esp,00000004
   81E1445E0000    and    ecx,00005E44   ; trash
   87EA           xchg   edx,ebp
  --- *812C240B104000*8B1424*83C404*87EA

 I guess you can imagine many more examples. The registers are choosen at random, and
 the offsets also differ in each version. The trash is completely randomly generated.
 I also made various versions for the instructions everywhere I found another way
 to do the same thing:

  mov eax, 1

  xor eax, eax
  inc eax

  push 1
  pop eax

  ... I think you got the point ;)

 I found for nearly everything a replacement, for opcodes and structure.
 In addition to this, the whole structure is changing everytime. I have a jump or a
 call at the end of each module to the next one. So I can randomly place all the 
 modules inside the source. Nice eh .. ;)
 Same goes of course for the data.


2.) Features

 Besides of nearly 100% variability of the entire code, this
 vck has these features :

 - Infects :
    + Win32 PE-Executables

 - Api Search Methods :
    + 2 byte comparsion methods
    + simple CRC ( look it up in Lethalminds API tutorial )
    + CRC32 ( look it up in Billy Belecebs Win - VWG )

 - Directory Travelling :
    + Windows Directory
    + System Directory

 - Anti Bait Checks :
    + Size

 - Anti Debugging :
    + Checks API's for SoftIce Breakpoint ( code from T2000's Chainsaw )

 - Encryption :
    + ROR/ROL, NEG, NOT, XOR, ADD/SUB


3.) Thanx & Greetz

 First of all I want to tell you that I really enjoyed to sit here,
 listening to the new Alice Cooper CD and trying to put some sense
 into my lines of code. I think it was worth the time I spend =)

 Eugene Kaspersky  - If you detect all viruses at the time of VB2001,
                     you'll get a sixpack of good german beer ! ;)
                     I know you can do it 
 Necronomicon      - go on coding, wheter with a group or not
 All German VX ppl - vielleicht gibt's ja doch mal ne deutsche Szene =)
 Team Matrix       - yeah, rock on.. 
 Dr. J             - ...need more coffee ;)
 Audiogalaxy guy   - this thingie rocks
 


 Others I want to mention here :
   entire KryptoCrew, DukeCS, rose, Anthraxx, Paul Zest,
   Vecna, Darkman, Dr. Seltsam, Eisbaer,
   the #CCC guys =), ...and many many more,...
   ( I am too lazy to write down everyone.. *g* )

4.) ToDo

 At the moment there is a lot to add here, so just the most important things .. =)

  + fix all bugs :P
  + add more layers of encryption, make decryptor also on the end
  + more variable code
  + ... and many many more things 

 NOT to do : PAYLOAD ( this is definately the last thing I think of ! )


5.) Thoughts and Ideas


 This last part will present some ideas and techniques i got or found
 while developing my Next Generation VCK. Not the big things, but
 if you are bored, just read it ... ;)

 /*/ Another way to receive the delta handle in Win9x & ME /*/

  This does not work on NT, but fine on all Win95 based systems.
  When starting the file, EAX contains the initial EIP. By using this
  we can simply retrieve the delta offset :
 
  .code
  Delta:
   mov ebp, eax
   sub ebp, offset Delta
   lea ecx, [ebp+offset Whatever]


 /*/ A possible Anti-Emulator Check /*/

  This has been tested under Win95, NT and ME, so I guess it will
  also work on 98 and 2000. When the file ist started, 
  the first 16 Bits of ESP and EBP are equal, this might be used to
  pass weak emulators, which do not correctly set these values.

  .code
   mov ebx, esp     ; get values
   mov edx, ebp
  
   shr ebx, 16d     ; clear last 16 Bit
   shr edx, 16d     ; could also be done with xor bx, bx .. etc

   cmp edx, ebx
   jne Emulated


 /*/ The Game /*/

  The game between the Antivirus and Virus Communities is still going on.
  Normally, there is a new Virus, which gives for a short time a point
  for the VX Scene, then there it gets detected and can be removed which
  gives a point for the AV's. So what can we do, to retrieve a keep the
  points for a longer time than the 12-24 hours they usually need to create
  a scanstring. The first way is polymorphism, which needs them to make a deeper
  analyzis of the virus, to test the strings. The next way is every new technique
  used by a virus. The last example for this was the stream infection, which made
  the AV's fear some undetectable viruses, which did not ( yet.. *g* ) exist.
  With every new technology the AV's need to understand it completely to react to
  it, so be creative. Even if you do things a lot different like usual in your virus
  they still need to understand it, because it could make their scanstrings useless and
  these 'we don't know if further payloads exists...' just look like shit inside
  the descriptions. The last thing I came about is a kind of denial of service ;)
  If the virus structure is like spaghetti code they need a bit longer to analyze it.
  And if there is a lot, a whole lot, of viruses like this, they have a lot to do,
  thats also a reason why I created NGVCK, because it makes such a lot of viruses possible
  and they have to develop a new technique to catch em all, which will hopefully not
  just be a fake.


 /*/ Writing a VCK /*/

  Ok, writing a VCK is a challenge and nice, but what is such a VCK
  useful for ? Maybe for Newbies to learn from the source, but I hardly
  think they do. For giving others the chance to infect others. Yes,
  this may be and I think this is what most VCK's are used for, sad 
  but true. A VCK might be nice, because it gives the AV'er a whole
  lot of work at once, they need to cope, because otherwise there
  would be several new viruses floating around. But wait, when talking
  about AV's, I think a VCK is also a big deal for them.
  They have the source codes of several viruses at once, they can
  take a look at fully commented source code and check if their
  heuristic engine catches them all. In addition to this, they
  can train their heuristics on all the generated viruses, which
  gives them a boost. So writing a VCK might not be that good for
  VX-Scene at all...

