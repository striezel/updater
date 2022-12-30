# Version history of updater

_(Note: This changelog focuses on the major changes between the different
versions. Therefore, it may not contain all changes. Especially smaller fixes or
improvements may be omitted.)_

## Version NEXT

__[maintenance]__

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

__[maintenance]__

* Newtonsoft.Json library is updated from 13.0.2 to 13.0.2.

__[maintenance]__

* Update certificate information for LibreOffice installers.

## Version 2022.11.03.0

__[maintenance]__

* Update certificate information for LibreOffice installers.

__[maintenance]__

* Update certificate information for CCleaner installers.

__[maintenance]__

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
