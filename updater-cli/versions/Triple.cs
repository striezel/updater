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

using System;

namespace updater_cli.versions
{
    /// <summary>
    /// utility class to represent a three-part numeric version, e.g. "11.2.3"
    /// </summary>
    public struct Triple : IComparable<Triple>, IEquatable<Triple>
    {
        /// <summary>
        /// major version number
        /// </summary>
        public uint major;

        /// <summary>
        /// minor version number
        /// </summary>
        public uint minor;

        /// <summary>
        /// patch level
        /// </summary>
        public uint patch;


        /// <summary>
        /// construct quartet from string value
        /// </summary>
        /// <param name="value">string value containing a dot-separated version, e.g. "11.2.7"</param>
        public Triple(string value)
        {
            major = 0;
            minor = 0;
            patch = 0;
            string[] parts = value.Split(new char[] { '.' });
            //If there are not enough parts, we just use zero instead.
            if (parts.Length >= 1)
                uint.TryParse(parts[0], out major);
            if (parts.Length >= 2)
                uint.TryParse(parts[1], out minor);
            if (parts.Length >= 3)
                uint.TryParse(parts[2], out patch);
        }


        /// <summary>
        /// gets the full version
        /// </summary>
        /// <returns>Returns a string containing the full version number.</returns>
        public string full()
        {
            return major.ToString() + "." + minor.ToString() + "." +
                patch.ToString();
        }


        public int CompareTo(Triple other)
        {
            if (ReferenceEquals(this, other))
                return 0;
            int c = major.CompareTo(other.major);
            if (c != 0)
                return c;
            c = minor.CompareTo(other.minor);
            if (c != 0)
                return c;
            return patch.CompareTo(other.patch);
        }


        public bool Equals(Triple other)
        {
            return ((major == other.major) && (minor == other.minor)
                && (patch == other.patch));
        }
    } //class
} //namespace
