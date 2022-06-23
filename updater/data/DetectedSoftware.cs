/*
    updater, command line interface
    Copyright (C) 2016  Dirk Stolle

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

namespace updater.data
{
    /// <summary>
    /// Represents a detected software.
    /// </summary>
    public struct DetectedSoftware : IComparable<DetectedSoftware>
    {
        /// <summary>
        /// default constructor
        /// </summary>
        public DetectedSoftware(string dispName = null, string dispVersion = null, string instPath = null, ApplicationType _appType = ApplicationType.Unknown)
        {
            displayName = dispName;
            displayVersion = dispVersion;
            installPath = instPath;
            appType = _appType;
        }


        /// <summary>
        /// Checks whether the entry contains some basic information.
        /// </summary>
        /// <returns>Returns true, if at least the name of the software is set.</returns>
        public bool containsInformation()
        {
            return !string.IsNullOrWhiteSpace(displayName);
        }


        /// <summary>
        /// comparison method for IComparable interface
        /// </summary>
        /// <param name="other">the other entry</param>
        /// <returns>Returns zero, i both instances are equal.
        /// Returns a value less than zero, if this comes before other.
        /// Returns a value greater than zero, if this comes after other.</returns>
        public int CompareTo(DetectedSoftware other)
        {
            if (ReferenceEquals(this, other))
                return 0;
            // First compare by display name.
            if (null == displayName)
            {
                if (null != other.displayName)
                    return 1;
            }
            else
            {
                int rc = displayName.CompareTo(other.displayName);
                if (rc != 0)
                    return rc;
            }
            // Compare by display version, if display names are equal.
            if (null == displayVersion)
            {
                if (null != other.displayVersion)
                    return 1;
            }
            else
            {
                int rc = displayVersion.CompareTo(other.displayVersion);
                if (rc != 0)
                    return rc;
            }
            // Finally compare by install path.
            if (null == installPath)
            {
                if (null != other.installPath)
                    return 1;
                else
                    return 0;
            }   
            return installPath.CompareTo(other.installPath);
        }


        /// <summary>
        /// Converts the struct into a string value, representing (parts of) its content.
        /// </summary>
        /// <returns>Returns a more readable string value.</returns>
        public override string ToString()
        {
            string result = displayName;
            if (!string.IsNullOrWhiteSpace(displayVersion))
                result += ", " + displayVersion;
            return result + ", " + appType.ToString();
        }


        /// <summary>
        /// displayed name of the software
        /// </summary>
        public string displayName;


        /// <summary>
        /// displayed version of the software
        /// </summary>
        public string displayVersion;


        /// <summary>
        /// path where the software is installed
        /// </summary>
        public string installPath;


        /// <summary>
        /// whether this is a 32 bit or 64 bit app
        /// </summary>
        public ApplicationType appType;
    } // struct
} // namespace
