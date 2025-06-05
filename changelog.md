# Version history of updater

_(Note: This changelog focuses on the major changes between the different
versions. Therefore, it may not contain all changes. Especially smaller fixes or
improvements may be omitted.)_

## Next Version

__[maintenance]__

* Update certificate information for SeaMonkey installers, because installers
  are no longer signed.

## Version 2025.05.31.0

__[changes]__

* Adjust search for newer version of IrfanView for the modified website.
* Adjust search for newer version of Microsoft Visual C++ 2015-2022
  Redistributable.

__[maintenance]__

* Update certificate information for Blender LTS installer.
* NLog library is updated from 5.4.0 to 5.5.0.

## Version 2025.04.30.0

__[changes]__

* Adjust search for newer version of TeamViewer for the modified website.

__[maintenance]__

* Update certificate information for Blender LTS installer.
* Update certificate information for FileZilla FTP Client installer.
* Update certificate information for LibreOffice installers.

## Version 2025.03.30.0

__[changes]__

* Starting with Git 2.49.0, no more 32-bit builds for Git are provided.
  Therefore the updater will now update 32-bit installations of Git to 64-bit
  installations, if it runs on a 64-bit OS.
* Starting with Stellarium 25.1, no more 32-bit builds for Stellarium are
  provided. Therefore the updater will now update 32-bit installations of
  Stellarium to 64-bit installations, if it runs on a 64-bit OS.
* The messages for download progress are adjusted for cases where the total
  size of the downloaded installer files are unknown.

__[maintenance]__

* Update certificate information for LibreOffice installers.
* Update certificate information for Opera GX installers.

## Version 2025.03.20.0

__[new features]__

* Update support for Microsoft Visual C++ 2015-2022 Redistributable is added.

__[changes]__

* Change update logic for proper handling of updates from GIMP 2.x to GIMP 3.0.

__[maintenance]__

* Update certificate information for Blender LTS installer.
* Update certificate information for Inno Setup installer.
* Update certificate information for KeePass installers.
* NLog library is updated from 5.3.4 to 5.4.0.

## Version 2025.01.31.0

__[changes]__

* Fix problem with search for newer versions of IrfanView.

__[maintenance]__

* Update certificate information for Pidgin installer.

## Version 2024.12.10.0

__[changes]__

* Revision updates of GIMP are now detected, too, i. e. when a version like
  for example 2.10.38 gets a minor update as version 2.10.38-1, the updater can
  now detect such updates and will offer them.

__[maintenance]__

* Update certificate information for Mumble installer.
* Update certificate information for PuTTY installers.

## Version 2024.11.11.0

__[breaking change]__

The required version of the .NET is bumped from .NET 6 to .NET 8.
If your system does not have .NET 8 yet, then you can download the .NET 8
runtime at <https://dotnet.microsoft.com/en-us/download/dotnet/8.0/runtime>.
Reason for that change is that Microsoft will end support for .NET 6 on
12th November 2024. From that date onwards, .NET 6 will not receive any
maintenance or security fixes, so this application is switching to .NET 8, the
current Long Term Support release of .NET.

__[new features]__

* Update support for ShareX is added.

__[changes]__

* Node.js updates will now track Node.js 22.x, because Node.js 22.x has moved
  into active Long Term Support (LTS).

__[maintenance]__

* Update certificate information for WinMerge installers.

## Version 2024.10.25.0

__[new features]__

* Update support for Inno Setup is added.
* Update support for Stellarium is added.

__[changes]__

* Fix problem with search for newer versions of Eclipse Temurin JDK 21 LTS and
  Eclipse Temurin JRE 21 LTS.
* Inkscape seems to have dropped support for 32-bit installers with version 1.4.
  As a result, the updater will now cross-grade existing 32-bit installations of
  Inkscape to 64-bit versions on 64-bit operating systems. On 32-bit operating
  systems where that is not an option, Inkscape will not be updated beyond
  version 1.3.2 which is the latest version that still had 32-bit installers.

__[maintenance]__

* Update certificate information for Eclipse Temurin JDK 8 LTS installers.
* Update certificate information for Eclipse Temurin JDK 11 LTS installers.
* Update certificate information for Eclipse Temurin JDK 17 LTS installers.
* Update certificate information for Eclipse Temurin JDK 21 LTS installers.
* Update certificate information for Eclipse Temurin JRE 8 LTS installers.
* Update certificate information for Eclipse Temurin JRE 11 LTS installers.
* Update certificate information for Eclipse Temurin JRE 17 LTS installers.
* Update certificate information for Eclipse Temurin JRE 21 LTS installers.

## Version 2024.09.30.0

__[new features]__

* Update support for Graphviz is added.

__[changes]__

* Blender updates will now use the newer 4.2 LTS release series, switching away
  from the previously used Blender 3.6 LTS series.

__[maintenance]__

* NLog library is updated from 5.3.3 to 5.3.4.

## Version 2024.08.31.0

__[changes]__

* Thunderbird updates are now using the ESR channel. This changes is needed to
  adapt to the new release model used by Thunderbird. To get more information
  about that, see <https://support.mozilla.org/en-US/kb/thunderbird-128-nebula-faq#w_why-is-thunderbird-128-labeled-as-128-0esr-when-previous-versions-were-not-called-esr>.
  Of all the new release channels, the ESR channel of Thunderbird uses a release
  model that is the closest to the release model in earlier versions
  (i. e. 115.x) and thus is closest to what users of the updater would expect.
  **Thunderbird 128 also dropped support for Windows 7 and Windows 8.1, so at
  least Windows 10 is required to use the new version of Thunderbird.**
* Fix failing search for newer versions of WinMerge.

__[maintenance]__

* NLog library is updated from 5.3.2 to 5.3.3.

## Version 2024.07.31.0

__[new features]__

* Update support for Doxygen is added.
* Update support for MariaDB 11.4 is added.

__[changes]__

* Add workaround for failing downloads of FileZilla Client.
* Adjust version detection for WinMerge.

__[maintenance]__

* Update certificate information for CCleaner installers.
* Update certificate information for Eclipse Temurin JDK 8 LTS installers.
* Update certificate information for Eclipse Temurin JRE 8 LTS installers.
* Update certificate information for Eclipse Temurin JDK 11 LTS installers.
* Update certificate information for Eclipse Temurin JRE 11 LTS installers.
* Update certificate information for Eclipse Temurin JDK 17 LTS installers.
* Update certificate information for Eclipse Temurin JRE 17 LTS installers.
* Update certificate information for Eclipse Temurin JDK 21 LTS installers.
* Update certificate information for Eclipse Temurin JRE 21 LTS installers.
* Update certificate information for Firefox ESR installers.

## Version 2024.06.28.0

__[announcement]__

* Microsoft's support for .NET 6 will end in November 2024. While this is still
  a few months in the future this also means that the updater will switch from
  .NET 6 to .NET 8, a newer Long Term Support release of .NET, in the coming
  months. Most likely this will not happen in the next one or two releases of
  the updater. However, you can expect the updater to require .NET 8 instead of
  the currently required .NET 6 by the end of the year. This notice is here to
  make sure users are aware of that upcoming change and have time to prepare
  accordingly.

__[new features]__

* Update support for Scribus is added.

__[changes]__

* The detection of installed 64-bit versions of LibreWolf, Opera and Opera GX is
  improved.

__[maintenance]__

* Update certificate information for Firefox Developer Edition installers.
* Update certificate information for Firefox (release channel) installers.
* Update certificate information for KeePass installers.
* Update certificate information for Thunderbird installers.
* Update certificate information for VLC media player installers.

## Version 2024.05.30.0

__[changes]__

* Adjust search for newer version of Acrobat Reader 2020.
* Fix problem where search for newer version of Acrobat Reader 2020 might hang
  and time out.
* Adjust search for newer version of CCleaner.
* Fix failing search for newer versions of FileZilla Client.

__[maintenance]__

* Update certificate information for GIMP installer.
* Update certificate information for Opera installers.

## Version 2024.05.03.0

__[changes]__

* Adjust search for newer version of Eclipse Temurin JDK 21 LTS and Eclipse
  Temurin JRE 21 LTS.

__[maintenance]__

* Update certificate information for Opera GX installers.
* NLog library is updated from 5.2.8 to 5.3.2.

## Version 2024.03.27.0

__[changes]__

* Adjust search for newer version of LibreOffice for the new version scheme.
* Adjust search for newer version of SeaMonkey for the new / modified website.

## Version 2024.02.29.0

__[new features]__

* Update support for WinMerge is added.

__[changes]__

* Adjust uninstallation routine for Shotcut to detect the proper uninstall
  binary.

__[maintenance]__

* Update certificate information for Acrobat Reader 2020 patches.
* Update certificate information for LibreOffice installers.
* Update certificate information for MariaDB 10.4 installer.
* Update certificate information for MariaDB 10.5 installer.
* Update certificate information for MariaDB 10.6 installer.
* Update certificate information for MariaDB 10.11 installer.
* Update certificate information for TeamViewer installer.

## Version 2024.01.25.0

__[new features]__

* Update support for Blender 3.6 LTS is added.
  (This may change to newer LTS versions of Blender in the future.)
* A new command-line parameter, `--progress`, is added to show the download
  progress while downloading updates.

__[maintenance]__

* NLog library is updated from 5.2.7 to 5.2.8.
* Update certificate information for Node.js installer.
* Update certificate information for Opera installer.

## Version 2023.12.11.0

__[new features]__

* Update support for HexChat is added.

__[changes]__

* Adjust search for newer version of Calibre.

__[maintenance]__

* NLog library is updated from 5.2.5 to 5.2.7.
* Update certificate information for IrfanView installer.

## Version 2023.11.14.0

__[new features]__

Update support for the following applications is added:

* Eclipse Temurin JDK 21 LTS
* Eclipse Temurin JRE 21 LTS
* LibreWolf

__[changes]__

* Adjust search for newer version of TreeSize Free for the modified website.

__[maintenance]__

* NLog library is updated from 5.2.4 to 5.2.5.

## Version 2023.10.12.0

__[maintenance]__

* Update certificate information for LibreOffice installers.
* Update silent install parameters for Shotcut due to installer change from NSIS
  to Inno Setup.
* Update certificate information for PDF24 Creator installer.

## Version 2023.09.14.0

__[maintenance]__

* NLog library is updated from 5.2.3 to 5.2.4.
* Update certificate information for Transmission installer.
* Fix certificate expiration date for TeamSpeak Client installer.

## Version 2023.08.20.0

__[changes]__

* Integrity checks for downloads of SeaMonkey will now use SHA-512 instead of
  SHA-1 checksums.

__[maintenance]__

* NLog library is updated from 5.2.2 to 5.2.3.
* Update certificate information for TreeSize Free installer.

## Version 2023.07.13.0

__[changes]__

* Adjust search for newer version of Node.js for the newer, updated website.
* Adjust search for newer version of TeamSpeak Client for the modified website.
* When the updater detects an old 32 bit version of TeamSpeak on a 64 bit OS,
  it will now migrate it to the 64 bit version of the TeamSpeak Client.

__[maintenance]__

* NLog library is updated from 5.2.0 to 5.2.2.

## Version 2023.06.10.0

__[maintenance]__

* Update certificate information for Git installer.
* Update certificate information for Shotcut installer.
* NLog library is updated from 5.1.4 to 5.2.0.

__[changes]__

* Adjust search for newer version of TeamViewer for the newer, updated website.

## Version 2023.05.04.0

__[maintenance]__

* Update certificate information for WinSCP installers.
* Update search for newer versions of PDF24 Creator.
* NLog library is updated from 5.1.3 to 5.1.4.

## Version 2023.04.07.0

__[new features]__

* Update support for MariaDB 10.11 is added.
* Update support for Opera GX is added.

__[changes]__

* The search for newer versions of TreeSize Free has been improved to handle a
  small change in the version number on the TreeSize website.

__[maintenance]__

* Update certificate information for CMake installers.
* Newtonsoft.Json library is updated from 13.0.2 to 13.0.3.
* NLog library is updated from 5.1.2 to 5.1.3.

## Version 2023.03.07.0

__[changes]__

* Adjust search for newer version of LibreOffice for the new URL pattern of the
  LibreOffice 64 bit installers.
* Adjust search for newer version of Transmission (BitTorrent client) for the
  newer, updated website of the Transmission project.

__[maintenance]__

* Update certificate information for KeePass installers.
* Update certificate information for LibreOffice installers.
* NLog library is updated from 5.1.1 to 5.1.2.

## Version 2023.01.28.0

__[maintenance]__

* Update certificate information for SeaMonkey installers.
* Update certificate information for LibreOffice installers.
* NLog library is updated from 5.1.0 to 5.1.1.

## Version 2022.12.20.0

__[changes]__

* The search for new PDF24 Creator versions can now also find the appropriate
  SHA-256 checksum for the MSI installer package.
* The search for newer versions of Inkscape has been improved to handle small
  changes in the URLs of MSI installer packages.

__[maintenance]__

* NLog library is updated from 5.0.5 to 5.1.0.

## Version 2022.11.26.0

__[changes]__

* The search for new Opera versions is adjusted to only include versions that
  provide a full installer and skip those versions that only provide the
  "autoupdate" binaries.
* Search for newer versions of Git has been adjusted to skip the releases that
  only contain MinGit binaries (e. g. MinGit v2.35.5.windows.1).

__[maintenance]__

* Update certificate information for CCleaner installers.
* Newtonsoft.Json library is updated from 13.0.1 to 13.0.2.
* Update certificate information for LibreOffice installers.

## Version 2022.11.03.0

__[maintenance]__

* Update certificate information for LibreOffice installers.
* Update certificate information for CCleaner installers.
* NLog library is updated from 5.0.4 to 5.0.5.

__[changes]__

* Updates of PuTTY will now uninstall the old version first, even if the old
  version is an MSI package (i. e. PuTTY 0.68 or later) to avoid potential
  conflicts with the new version.

## Version 2022.10.06.0

__[changes]__

Search for newer versions of CDBurnerXP has been adjusted for the partially
defect website. The newest available version can now be found despite the fact
that the download page shows an error.

__[new features]__

* Support to update Adobe Acrobat Reader 2017 to Acrobat Reader 2020 is added.
* Update support for Adobe Acrobat Reader 2020 is added.

## Version 2022.09.20.0

__[new features]__

Update support for the following applications is added.

* IrfanView
* MariaDB 10.3
* MariaDB 10.4

## Version 2022.09.04.0

__[changes]__

Adjust search for newer version of Transmission (BitTorrent client) for the
newer, updated website of the Transmission project.

__[maintenance]__

* NLog library is updated from 5.0.2 to 5.0.4.

## Version 2022.08.29.1

__[maintenance]__

* Remove language from installer that is not supported by Inno Setup 6 version
  on the GitHub Actions runners (Greek, Hungarian, Scottish Gaelic).

## Version 2022.08.29.0

__[maintenance]__

* Fix problem with installer not containing all required files for a proper
  installation of the software.
* The installer will now offer few more languages during installation.
  (Those are only used by the installer. The program itself still only uses
   English as language.)

## Version 2022.08.28.0

__[breaking change]__

The required version of the .NET is bumped from .NET Framework 4.7.2 to .NET 6.
If your system does not have .NET 6 yet, then you can download the .NET 6
runtime at <https://dotnet.microsoft.com/en-us/download/dotnet/6.0/runtime>.

__[breaking change]__

Update support for Audacity is removed.
Primary reason for the removal are some concerns over the telemetry options that
got introduced in newer versions of Audacity. For the (rather long) discussion
about Audacity's telemetry stuff see
<https://github.com/audacity/audacity/pull/835>.

__[new features]__

Update support for HeidiSQL is added.

__[changes]__

Downloads for 7-Zip will now use HTTPS (instead of HTTP) consistently.

__[maintenance]__

* NLog library is updated from 5.0.1 to 5.0.2.

## Version 2022.07.14.0

__[new features]__

Update support for the following applications is added:

* Eclipse Temurin JDK 17 LTS
* Eclipse Temurin JRE 8 LTS _(formerly AdoptOpenJDK JRE 8)_
* Eclipse Temurin JRE 11 LTS _(formerly AdoptOpenJDK JRE 11)_
* Eclipse Temurin JRE 17 LTS
* MariaDB 10.5
* MariaDB 10.6
* TeamSpeak Client

__[changed]__

* Java JDK 8 updates are switched from AdoptOpenJDK JDK 8 LTS to Eclipse Temurin
  JDK 8 LTS. This is due to the fact that AdoptOpenJDK moved to the Eclipse
  Foundation. See
  <https://blog.adoptopenjdk.net/2021/03/transition-to-eclipse-an-update/>
  for more information on that. 
* Java JDK 11 updates are switched from AdoptOpenJDK JDK 11 LTS to Eclipse
  Temurin JDK 11 LTS. This is due to the fact that AdoptOpenJDK moved to the
  Eclipse Foundation. See the link above for more information.

__[maintenance]__

* NLog library is updated from 4.7.10 to 5.0.1.

## Version 2021.06.23.0

__[new features]__

Update support for the following applications is added:

* AdoptOpenJDK JDK 8 LTS
* AdoptOpenJDK JDK 11 LTS
* Shotcut
* TeamViewer
* TreeSize Free

## Version 2021.06.12.0

__[breaking change]__

The required version of the .NET Framework is bumped from 4.6.1 to 4.7.2.

__[changed]__

The timeout for some software downloads that are known to sometimes hang
indefinitely has been shortened to avoid very long waiting times before those
downloads time out.

__[maintenance]__

* NLog library is updated from 4.7.8 to 4.7.10.

## Version 2021.03.12.0

__[new features]__

Update support for the following applications is added:

* CMake
* Git for Windows
* Node.js LTS
* Transmission _(BitTorrent client)_

__[changes]__

* The installer does now support the following additional languages:
  Dutch, Finnish, French, Hebrew, Italian, Japanese, Portuguese, Russian,
  Spanish, and Turkish. (Previous installer versions only supported German and
  English.)
* Integrity checks for downloads of Opera will now use SHA-256 instead of MD5
  checksums.
* Support for using MD5 checksums in integrity checks of downloads is removed.

__[maintenance]__

* NLog library is updated from 4.7.5 to 4.7.8.

## Version 2020.10.06.0

__[breaking change]__

The required version of the .NET Framework is bumped from 4.0 Client Profile to
4.6.1.

__[changes]__

* Integrity checks for downloads of Inkspace will now use SHA-256 instead of MD5
  checksums, because Inkspace provides those starting with version 1.0.

__[maintenance]__

* NLog library is updated from 4.7.2 to 4.7.5.

## Version 2020.06.05.0

__[maintenance]__

* NLog library is updated from 4.4.12 to 4.7.2.
* Remove NuGet package artifacts from repository.

## Version 2019.08.22.0

__[breaking change]__

Update support for Adobe Shockwave is removed. Adobe has discontinued support
for Shockwave on April 9, 2019, according to
<https://helpx.adobe.com/shockwave/shockwave-end-of-life-faq.html>.

## Version 2019.02.28.0

__[new features]__

Update support for the following applications is added:

* Adobe Shockwave

## Version 2018.03.28.0

__[changes]__

* Update search for KeePass 2 is adjusted to changes on its website.
* A problem with the update search for newest Opera browser version is fixed.
