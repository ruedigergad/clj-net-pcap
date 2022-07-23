                           Instructions on adding 
               jnetpcap library to java projects in eclipse
                      Last updated: 2009-09-23 by MWB
                      

jNetPcap is a java project that comes with a required native shared library. The
requirement of a native library typically adds confusion and presents 
difficulty for many as to how properly setup a project in eclipse to reference 
jNetPcap library correctly.

There are several ways that jNetPcap can be added to your existing java project
 in Eclipse IDE. Let me briefly outline them here and then lets go through the 
 detailed steps of actually creating a proper build path so your project will 
 compile with jNetPcap.
 
1) Create a jNetPcap "user library" which has all the neccessary path components 
configured and add that to the project's build path

2) Add jnetpcap's jar file and native library directory path to project's build 
path

3) Add jnetpcap's jar file to project's build path, but put the native library 
in global environment variable (LD_LIBRARY_PATH under unix and PATH variable 
under windows)

4) Add jnetpcap's jar file to project's build path, but copy the neccessary 
native library to a system library directory (/usr/lib under unix or 
\windows\SystemXX under windows).

We recommend approaches #1 and #2 for development. If you are creating a single 
jnetpcap dependent project, approach #2 may be all you need. On the other hand 
if you want to set it up once for many projects, approach #1 is what we 
recommend.

Setup #3 and #4 are no recommended for a build environment, and will not be 
discussed here.

*** First thing first

First thing you have to do is download and install (or unzip) the jNetPcap 
installation package. You do not have to install (unzip or untar) the 
installation package under an Eclipse workspace, unless you want to for a 
specific. The installation can be external to the workspace. Since each jNetPcap
installation package installs under a unique directory path, you can easily have
multiple versions of the library and switch between them when needed. Both 
installable and extractable unix and windows packages are provided. Under unix 
the packager installed packages are intended for production environments, that 
have a jNetPcap requirement. At same time the JAR and unzip packages are 
provided incase you need multiple versions of the library where you can extract 
on your own and easily switch between them.
In the below examples we are going to assume that we extracted 2 versions of 
jnetpcap library under "c:\libs" directory (on a windows platform). For unix you 
can assume a home directory based path "$HOME/libs" or something similar. In the
"libs" directory we installed version jnetpcap-1.2 and jnetpcap-1.3.b0010.

We are also going to assume that the user has extracted/installed all 3 packages
of jnetpcap (the executable package), jnetpcap-javadoc, jnetpcap-src for both 
versions above.

*** Setup #1 - Setting up a "user library" under Eclipse (recommended setup)

Setting up a "user library" under eclipse IDE platform, is a way for you to 
define in one place a single or multiple java libraries along with all of their 
requirements such as "native libraries", javadoc documentation and where to do 
lookups for source code incase you want to drill down into a function. This is 
also a neat way to change versions of the library globally without having to 
modify build paths for each project you have setup.

To create a new "user library" under Elicpse:
1) Open Preferences dialog
Window->preferences
In the dialog select "User Libraries"
either search "user" in dialog's search box 
or
Java->Build Path->User Libraries

2) Then click "New..." button or "Import..." if you already have a user library 
definition saved.

3) Enter "jNetPcap" for the name of the user library. Leave the checkbox 
"System Library" as OFF.

4) Next we want to add actual java jar files that make up this user library
Click the "Add JARs..." button

5) Select the "jnetpcap.jar" file under where jnetpcap was installed or 
extracted to (under c:\libs for our example.)

6) That should add tree content to your "user library". Expand the 
"jnetpcap.jar" file that appeared under "jnetpcap" user library.

7) Select "Native library location" and click "Edit..." button. There again 
select the directory where jNetPcap has been installed to 
(our C:\libs\jnetpcap-1.2 as an example).

8) Also select and "Edit..." the locations to "Javadoc location" and "Source 
attachment". You can point directly at the ZIP and tar files without having to 
extract those first.

9) Optionally once the "user library" is setup, you can export it to a file so 
that you can import it into other Eclipse "workspaces" or if you want to keep a 
safe copy.

10) Last thing to do is to hit the "OK" button and we are done

Now that a "user library" has been setup, you can add this user library to any 
of your Eclipse projects that need jnetpcap. You add the "user library" to each 
project's "Build Path". To do that, here are the instructions:

1) Select the project you want to add jnetpcap user library to and open its 
properties:
Project->Properties->Java Build Path

or right click on the project in "Package Explorer" and select

Build Path->Configure Build Path

2) Select the "Libraries" TAB and click "Add Library..." button

3) In the "Add Library" dialog box that shows up, select "User Library" and 
click "Next >" button at the bottom.

4) Your newly created "user library" should show up in a list of 1 or more 
"user libraries". Each library has a check box and you want to select the check 
box next to "jnetpcap"

5) Optionally, if you haven't setup a jnetpcap "user library" yet, there is a 
"User Libraries..." button within this dialog that lets you create one right 
there.

6) We are done, so we click the "Finish" button.

You can do this for all other java projects in your workspace that need jnetpcap
library.

The benefit of using a "user library" is that you can easily change the version 
of jnetpcap the "user library" is referencing by modifying the paths for jar, 
native, javadoc and source locations in this one place. You may also create 
multiple "user libraries" that reference different versions of 'jnetpcap' user 
library. For example, you can setup a "jnetpcap-production" library that 
references a production version of jnetpcap and additional user libraries such 
as "jnetpcap-latest", "jnetpcap-1.3.b0010", etc. Then decide which of your own 
projects should be using which version of the library.

The source and javadocs will automatically be changed as well, making this a 
very robust development environment for your project.

*** Setup #2 - Adding jnetpcap JAR file directly to your project

Another approach is to add the jnetpcap.jar file (from directory 
c:\lib\jnetpcap-1.2 for example) to your project's build path. Once added you 
can still modify for that particular library where the required native library 
resides. This is a good approach if you only have a single java project that 
needs jnetpcap.

To add jnetpcap to your project's build path:

1) Select the project you want to add jnetpcap library to and open its 
properties:

Project->Properties->Java Build Path
or right click on the project in "Package Explorer" and select
Build Path->Configure Build Path

2) Click the "Add External JARs..." button (or "Add JARs..." if you installed 
jnetpcap within the Eclipse workspace)

3) Go to your installation directory (c:\libs\jnetpcap-1.2 for example) and 
select the jnetpcap.jar file and click "Open" button to add the jar file to the 
project's build path.

4) A "jnetpcap.jar" file should show up in the "build path" tree. Expand it.

5) Select "Native library location" and click "Edit..." button.

6) Select the directory where the native file resides (c:\libs\netpcap-1.2 for 
example).

7) Optionally, you can do the same for "Javadoc location" and "Source 
attachment". You do not need to expand them from their zip or tar forms. 
Eclipse will take them in archive form.

8) Lastly, click the "OK" button at the bottom

Now jnetpcap library and its native library are added to your project. If you 
added javadoc and source locations, you can also see javadocs in Eclipse (hover 
or javadoc display) and drill down into jnetpcap methods and view their source.

For more information please read online userguide at:
http://www.jnetpcap.com/userguide

This document reference:
http://www.jnetpcap.com/eclipse