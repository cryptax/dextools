
./app contains a demo application where a method named thisishidden() in class MrHyde is hidden from disassemblers but nevertheless called by the app.

      ./demo/classes.dex.hidden	  method thisishidden() is hidden from 
      				  decompilers

      ./demo/DrJekyll-release.apk example of APK where thisishidden()  is
      				  hidden but nevertheless called by the app

      ./src			  sources of the app - DEX needs to
      				  be patched to hide thisishidden()


Code is released using the Open Source BSD 2-Clause License (http://opensource.org/licenses/BSD-2-Clause)
