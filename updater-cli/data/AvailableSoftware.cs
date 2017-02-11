/*
    This file is part of the updater command line interface.
    Copyright (C) 2016, 2017  Dirk Stolle

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

using System;
using System.Xml;
using System.Xml.Serialization;

namespace updater_cli.data
{
    /// <summary>
    /// holds information about an available piece of software
    /// </summary>
    [XmlRoot(ElementName = "available_software")]
    public class AvailableSoftware : IComparable<AvailableSoftware>
    {
        /// <summary>
        /// default constructor
        /// </summary>
        public AvailableSoftware()
        {
            Name = null;
            newestVersion = null;
            match32Bit = null;
            match64Bit = null;
            install32Bit = null;
            install64Bit = null;
        }


        /// <summary>
        /// constructor with initial values
        /// </summary>
        /// <param name="_name">name of the software</param>
        /// <param name="_newestVersion">newest version</param>
        /// <param name="_regex32">regular expression to match for the 32 bit version</param>
        /// <param name="_regex64">regular expression to match for the 64 bit version</param>
        /// <param name="_install32">installer information for the 32 bit variant of the software</param>
        /// <param name="_install64">installer information for the 64 bit variant of the software</param>
        public AvailableSoftware(string _name, string _newestVersion,
            string _regex32 = null, string _regex64 = null,
            InstallInfo _install32 = null, InstallInfo _install64 = null)
        {
            Name = _name;
            newestVersion = _newestVersion;
            match32Bit = _regex32;
            match64Bit = _regex64;
            install32Bit = _install32;
            install64Bit = _install64;
        }
        
        /// <summary>
        /// generic name of the software
        /// </summary>
        [XmlElement(ElementName = "name", IsNullable = false)]
        public string Name;


        /// <summary>
        /// newest version of the software
        /// </summary>
        [XmlElement(ElementName = "newest", IsNullable = false)]
        public string newestVersion;


        /// <summary>
        /// regular expression to match for the 32 bit version
        /// </summary>
        [XmlElement(ElementName = "regex32", IsNullable = true)]
        public string match32Bit;


        /// <summary>
        /// regular expression to match for the 64 bit version
        /// </summary>
        [XmlElement(ElementName = "regex64", IsNullable = true)]
        public string match64Bit;


        /// <summary>
        /// installer information for the 32 bit variant of the software
        /// (Might be null, if there is no 32 bit variant.)
        /// </summary>
        [XmlElement(ElementName = "install32", IsNullable = true)]
        public InstallInfo install32Bit;


        /// <summary>
        /// installer information for the 64 bit variant of the software
        /// (Might be null, if there is no 64 bit variant.)
        /// </summary>
        [XmlElement(ElementName = "install64", IsNullable = true)]
        public InstallInfo install64Bit;



        /// <summary>
        /// comparison method for IComparable interface
        /// </summary>
        /// <param name="other">the other entry</param>
        /// <returns>Returns zero, i both instances are equal.
        /// Returns a value less than zero, if this comes before other.
        /// Returns a value greater than zero, if this comes after other.</returns>
        public int CompareTo(AvailableSoftware other)
        {
            if (ReferenceEquals(this, other))
                return 0;
            //First compare by name.
            if (null == Name)
            {
                if (null != other.Name)
                    return 1;
            }
            else
            {
                var rc = Name.CompareTo(other.Name);
                if (rc != 0)
                    return rc;
            }
            //Now compare by version.
            if (null == newestVersion)
            {
                if (null != other.newestVersion)
                    return 1;
                else
                    return 0;
            }
            else
            {
                return newestVersion.CompareTo(other.newestVersion);
            }
        }
    } //class
} //namespace
