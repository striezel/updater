﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2022, 2024  Dirk Stolle

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
    /// Utility class to represent a four-part version, e.g. "11.23.4.5", that
    /// shrinks to a three-part version when the last version number is zero.
    /// </summary>
    public struct ShrinkingQuartet : IComparable<ShrinkingQuartet>, IEquatable<ShrinkingQuartet>,
        IComparable<Quartet>, IEquatable<Quartet>
    {
        /// <summary>
        /// major version number, e.g. the 11 in 11.23.4.5
        /// </summary>
        public uint major;

        /// <summary>
        /// minor version number, e.g. the 23 in 11.23.4.5
        /// </summary>
        public uint minor;

        /// <summary>
        /// patch level, e.g. the 4 in 11.23.4.5
        /// </summary>
        public uint patch;

        /// <summary>
        /// build number, e.g. the 5 in 11.23.4.5
        /// </summary>
        public uint build;

        /// <summary>
        /// Construct quartet from string value.
        /// </summary>
        /// <param name="value">string value containing a dot-separated version, e.g. "11.2.3.45"</param>
        public ShrinkingQuartet(string value)
        {
            major = 0;
            minor = 0;
            patch = 0;
            build = 0;
            string[] parts = value.Split(['.']);
            // If there are less than four parts, we just assume zero.
            uint.TryParse(parts[0], out major);
            if (parts.Length >= 2)
                uint.TryParse(parts[1], out minor);
            if (parts.Length >= 3)
                uint.TryParse(parts[2], out patch);
            if (parts.Length >= 4)
                uint.TryParse(parts[3], out build);
        }


        /// <summary>
        /// Gets the full version.
        /// </summary>
        /// <returns>Returns a string containing the full version number.</returns>
        public readonly string full()
        {
            if (build != 0)
                return major.ToString() + "." + minor.ToString() + "."
                    + patch.ToString() + "." + build.ToString();
            else
                return major.ToString() + "." + minor.ToString() + "." + patch.ToString();
        }


        public override readonly string ToString()
        {
            return full();
        }


        public readonly bool Equals(ShrinkingQuartet other)
        {
            return (major == other.major) && (minor == other.minor)
                && (patch == other.patch) && (build == other.build);
        }


        public readonly bool Equals(Quartet other)
        {
            return (major == other.major) && (minor == other.minor)
               && (patch == other.patch) && (build == other.build);
        }


        public override readonly bool Equals(object obj)
        {
            // There are two possible compatible types: ShrinkingQuartet and plain Quartet.
            if (obj is ShrinkingQuartet sq)
                return Equals(sq);
            return (obj is Quartet q) && Equals(q);
        }


        public override readonly int GetHashCode()
        {
            return Convert.ToInt32((major ^ minor ^ patch ^ build) & 0x7FFFFFFFu);
        }


        public readonly int CompareTo(ShrinkingQuartet other)
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


        public readonly int CompareTo(Quartet other)
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


        public static bool operator <(ShrinkingQuartet a, ShrinkingQuartet b)
        {
            return a.CompareTo(b) < 0;
        }


        public static bool operator >(ShrinkingQuartet a, ShrinkingQuartet b)
        {
            return a.CompareTo(b) > 0;
        }
    }
}
