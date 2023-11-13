/*
    This file is part of the updater command line interface.
    Copyright (C) 2023  Dirk Stolle

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
    /// Utility class to represent a four-part version with dash, e.g. "11.23.4-5",
    /// that shrinks to a triple when the patch version is zero.
    /// </summary>
    public struct ShrinkingDashedQuartet : IComparable<ShrinkingDashedQuartet>, IEquatable<ShrinkingDashedQuartet>
    {
        /// <summary>
        /// major version number, e. g. the 11 in 11.23.4-5
        /// </summary>
        public uint major;

        /// <summary>
        /// minor version number, e. g. the 23 in 11.23.4-5
        /// </summary>
        public uint minor;

        /// <summary>
        /// patch level, e. g. the 4 in 11.23.4-5
        /// </summary>
        public uint patch;

        /// <summary>
        /// build number, e. g. the 5 in 11.23.4-5
        /// </summary>
        public uint build;


        /// <summary>
        /// construct quartet from string value
        /// </summary>
        /// <param name="value">string value containing a dot-separated version, e.g. "11.2.7-23"</param>
        public ShrinkingDashedQuartet(string value)
        {
            major = 0;
            minor = 0;
            patch = 0;
            build = 0;
            string[] dashed_parts = value.Split(new char[] { '-' });
            string[] parts = dashed_parts[0].Split(new char[] { '.' });

            // If there are less than three parts, we just assume zero.
            uint.TryParse(parts[0], out major);
            if (parts.Length >= 2)
                uint.TryParse(parts[1], out minor);
            if (parts.Length >= 3)
                uint.TryParse(parts[2], out patch);
            if (dashed_parts.Length >= 2)
                uint.TryParse(dashed_parts[1], out build);
        }


        /// <summary>
        /// Gets the full version.
        /// </summary>
        /// <returns>Returns a string containing the full version number.</returns>
        public string full()
        {
            if (patch == 0)
                return major.ToString() + "." + minor.ToString() + "-"
                    + build.ToString();
            else
                return major.ToString() + "." + minor.ToString() + "."
                    + patch.ToString() + "-" + build.ToString();
        }


        public override string ToString()
        {
            return full();
        }


        public bool Equals(Quartet other)
        {
            return (major == other.major) && (minor == other.minor)
                && (patch == other.patch) && (build == other.build);
        }


        public bool Equals(ShrinkingDashedQuartet other)
        {
            return (major == other.major) && (minor == other.minor)
                && (patch == other.patch) && (build == other.build);
        }


        public override bool Equals(object obj)
        {
            if (obj is Quartet q)
                return Equals(q);
            return (obj is ShrinkingDashedQuartet sdq) && Equals(sdq);
        }


        public override int GetHashCode()
        {
            return Convert.ToInt32((major ^ minor ^ patch ^ build) & 0x7FFFFFFFu);
        }


        public int CompareTo(ShrinkingDashedQuartet other)
        {
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


        public static bool operator <(ShrinkingDashedQuartet a, ShrinkingDashedQuartet b)
        {
            return a.CompareTo(b) < 0;
        }


        public static bool operator >(ShrinkingDashedQuartet a, ShrinkingDashedQuartet b)
        {
            return a.CompareTo(b) > 0;
        }
    } // class
} // namespace
