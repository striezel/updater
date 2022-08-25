# Version history of updater

_(Note: This changelog focuses on the major changes between the different
versions. Therefore, it may not contain all changes. Especially smaller fixes or
improvements may be omitted.)_

## Version NEXT

__[breaking change]__

The required version of the .NET is bumped from .NET Framework 4.7.2 to .NET 6.

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
