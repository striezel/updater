# Version history of updater

_(Note: This changelog focuses on the major changes between the different
versions. Therefore, it may not contain all changes. Especially smaller fixes or
improvements may be omitted.)_

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
