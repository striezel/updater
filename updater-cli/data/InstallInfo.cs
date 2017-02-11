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
    public class InstallInfo
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
