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

namespace updater.versions
{
    /// <summary>
    /// Utility class to represent a three-part numeric version, e.g. "11.2.3".
    /// </summary>
    public struct Triple : IComparable<Triple>, IEquatable<Triple>
    {
        /// <summary>
        /// major version number, e. g. the 11 in 11.2.3
        /// </summary>
        public uint major;

        /// <summary>
        /// minor version number, e. g. the 2 in 11.2.3
        /// </summary>
        public uint minor;

        /// <summary>
        /// patch level, e. g. the 3 in 11.2.3
        /// </summary>
        public uint patch;


        /// <summary>
        /// Constructs a Triple from string value.
        /// </summary>
        /// <param name="value">string value containing a dot-separated version, e.g. "11.2.7"</param>
        public Triple(string value)
        {
            major = 0;
            minor = 0;
            patch = 0;
            string[] parts = value.Split(new char[] { '.' });
            // If there are not enough parts, we just use zero instead.
            if (parts.Length >= 1)
                uint.TryParse(parts[0], out major);
            if (parts.Length >= 2)
                uint.TryParse(parts[1], out minor);
            if (parts.Length >= 3)
                uint.TryParse(parts[2], out patch);
        }


        /// <summary>
        /// Gets the full version.
        /// </summary>
        /// <returns>Returns a string containing the full version number.</returns>
        public string full()
        {
            return major.ToString() + "." + minor.ToString() + "." +
                patch.ToString();
        }


        public override string ToString()
        {
            return full();
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


        public static bool operator <(Triple a, Triple b)
        {
            return a.CompareTo(b) < 0;
        }


        public static bool operator >(Triple a, Triple b)
        {
            return a.CompareTo(b) > 0;
        }
    } // class
} // namespace
