/*
    This file is part of the updater command line interface.
    Copyright (C) 2017  Dirk Stolle

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using System.Xml.Serialization;

namespace updater_cli.data
{
    /// <summary>
    /// holds information about an installer
    /// </summary>
    [XmlRoot(ElementName = "installinfo")]
    public abstract class InstallInfo
    {
        /// <summary>
        /// default constructor
        /// </summary>
        public InstallInfo()
        {
            downloadUrl = null;
            algorithm = HashAlgorithm.Unknown;
            checksum = null;
            silentSwitches = null;
            defaultPath32 = null;
            defaultPath64 = null;
        }


        /// <summary>
        /// constructor with initial value parameters
        /// </summary>
        /// <param name="_downloadUrl">URL where the installer can be downloaded</param>
        /// <param name="_algo">hash algorithm that was used to create or verify the checksum</param>
        /// <param name="_check">checksum for the installer - hexadecimal representation</param>
        /// <param name="_silent">switches for silent installation</param>
        /// <param name="_def32">default installation path on 32 bit systems</param>
        /// <param name="_def64">default installation path on 64 bit systems</param>
        public InstallInfo(string _downloadUrl, HashAlgorithm _algo, string _check, string _silent, string _def32, string _def64)
        {
            downloadUrl = _downloadUrl;
            algorithm = _algo;
            checksum = _check;
            silentSwitches = _silent;
            defaultPath32 = _def32;
            defaultPath64 = _def64;
        }


        /// <summary>
        /// determines whether or not this instance has checksum information
        /// </summary>
        /// <returns>Returns true, if there is a checksum.
        /// Returns false, if there is no checksum.</returns>
        public bool hasChecksum()
        {
            return ((algorithm != HashAlgorithm.Unknown)
                && !string.IsNullOrWhiteSpace(checksum));
        }


        /// <summary>
        /// whether the installer is a simple exe file, not using msiexec
        /// </summary>
        /// <returns>Returns true, if the installer does not use msiexec.</returns>
        abstract public bool isExe();


        /// <summary>
        /// whether the installer uses msiexec
        /// </summary>
        /// <returns>Returns true, if the installer uses msiexec.</returns>
        abstract public bool isMsi();


        /// <summary>
        /// URL where the installer can be downloaded
        /// </summary>
        [XmlElement(ElementName = "url", IsNullable = true)]
        public string downloadUrl;


        /// <summary>
        /// hash algorithm that was used to create or verify the checksum
        /// </summary>
        [XmlElement(ElementName = "algorithm", IsNullable = false)]
        public HashAlgorithm algorithm;


        /// <summary>
        /// checksum for the installer - hexadecimal representation
        /// (e.g. "7772433567cb18608519f649f981e38a0be12c26" for a SHA1 checksum)
        /// </summary>
        [XmlElement(ElementName = "checksum", IsNullable = true)]
        public string checksum;


        /// <summary>
        /// switches for silent installation
        /// </summary>
        [XmlElement(ElementName = "silent_switches", IsNullable = true)]
        public string silentSwitches;


        /// <summary>
        /// default installation path on 32 bit systems
        /// </summary>
        [XmlElement(ElementName = "defaultPath32", IsNullable = true)]
        public string defaultPath32;


        /// <summary>
        /// default installation path on 64 bit systems
        /// </summary>
        [XmlElement(ElementName = "defaultPath64", IsNullable = true)]
        public string defaultPath64;
    } //class
} //namespace
