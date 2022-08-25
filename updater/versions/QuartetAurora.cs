/*
    This file is part of the updater command line interface.
    Copyright (C) 2018  Dirk Stolle

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
using System.Text.RegularExpressions;

namespace updater.versions
{
    /// <summary>
    /// Utility class to represent a four part version as seen in Firefox Aurora, e.g. "61.0b8".
    /// </summary>
    public class QuartetAurora : IComparable<QuartetAurora>, IEquatable<QuartetAurora>
    {
        /// <summary>
        /// major version number, e.g. the 61 in "61.0b8"
        /// </summary>
        public uint major;

        /// <summary>
        /// minor version number, e.g. the 0 (zero) in "61.0b8"
        /// </summary>
        public uint minor;

        /// <summary>
        /// patch letter, e.g. the b in "61.0b8"
        /// </summary>
        public char patch;

        /// <summary>
        /// build number, e.g. the 8 in "61.0b8"
        /// </summary>
        public uint build;

        /// <summary>
        /// regular expression for splitting the second part of the version number
        /// </summary>
        private static readonly Regex reg = new Regex("^([0-9]+)([a-z])([0-9]+)$");


        /// <summary>
        /// Constructs an empty quartet.
        /// </summary>
        public QuartetAurora()
        {
            major = 0;
            minor = 0;
            patch = 'b';
            build = 0;
        }


        /// <summary>
        /// Constructs a quartet from string value.
        /// </summary>
        /// <param name="value">string value containing a dot-separated version, e.g. "61.0b8"</param>
        public QuartetAurora(string value)
        {
            string[] parts = value.Split(new char[] { '.' });
            // If there are not enough parts or parsing fails, we just assume zero.
            if (!uint.TryParse(parts[0], out major))
            {
                major = 0;
            }
            if (parts.Length >= 2)
            {
                Match m = reg.Match(parts[1]);
                if (!m.Success)
                {
                    minor = 0;
                    patch = 'b';
                    build = 0;
                }
                else
                {
                    if (!uint.TryParse(m.Groups[1].Value, out minor))
                    {
                        minor = 0;
                    }
                    patch = m.Groups[2].Value[0];
                    if (!uint.TryParse(m.Groups[3].Value, out build))
                    {
                        build = 0;
                    }
                }
            }
            else
            {
                minor = 0;
                patch = 'b';
                build = 0;
            }
        }


        /// <summary>
        /// Gets the full version.
        /// </summary>
        /// <returns>Returns a string containing the full version number.</returns>
        public string full()
        {
            return major.ToString() + "." + minor.ToString() + patch.ToString()
                + build.ToString();
        }


        public override string ToString()
        {
            return full();
        }


        public bool Equals(QuartetAurora other)
        {
            return (major == other.major) && (minor == other.minor)
                && (patch == other.patch) && (build == other.build);
        }


        public int CompareTo(QuartetAurora other)
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


        public static bool operator <(QuartetAurora a, QuartetAurora b)
        {
            return a.CompareTo(b) < 0;
        }


        public static bool operator >(QuartetAurora a, QuartetAurora b)
        {
            return a.CompareTo(b) > 0;
        }
    } // class
} // namespace
