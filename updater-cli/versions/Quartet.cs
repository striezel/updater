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
    /// utility class to represent a four-part version, e.g. "11.23.4.5"
    /// </summary>
    public struct Quartet : IComparable<Quartet>
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
        /// build number
        /// </summary>
        public uint build;


        /// <summary>
        /// construct quartet from string value
        /// </summary>
        /// <param name="value">string value containing a dot-separated version, e.g. "11.2.7.23"</param>
        public Quartet(string value)
        {
            major = 0;
            minor = 0;
            patch = 0;
            build = 0;
            string[] parts = value.Split(new char[] { '.' });
            if (parts.Length < 4)
            {
                return;
            }
            uint.TryParse(parts[0], out major);
            uint.TryParse(parts[1], out minor);
            uint.TryParse(parts[2], out patch);
            uint.TryParse(parts[3], out build);
            return;
        }


        /// <summary>
        /// gets the full version
        /// </summary>
        /// <returns>Returns a string containing the full version number.</returns>
        public string full()
        {
            return major.ToString() + "." + minor.ToString() + "." +
                patch.ToString() + "." + build.ToString();

        }

        public int CompareTo(Quartet other)
        {
            if (ReferenceEquals(this, other))
                return 0;
            int c = major.CompareTo(other.major);
            if (c != 0)
                return c;
            c = minor.CompareTo(other.minor);
            if (c != 0)
                return c;
            c = patch.CompareTo(other.patch);
            if (c != 0)
                return c;
            return build.CompareTo(other.build);
        }
    } //class
} //namespace
