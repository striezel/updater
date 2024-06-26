﻿/*
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

using updater.software;

namespace updater.data
{
    /// <summary>
    /// Represents an entry in a status query.
    /// </summary>
    public class QueryEntry
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        public QueryEntry(ISoftware sw, DetectedSoftware _detected, bool _needsUpdate, ApplicationType _type)
        {
            software = sw;
            detected = _detected;
            needsUpdate = _needsUpdate;
            type = _type;
        }


        /// <summary>
        /// the corresponding software instance
        /// </summary>
        public ISoftware software;


        /// <summary>
        /// detected software entry
        /// </summary>
        public DetectedSoftware detected;


        /// <summary>
        /// whether the software can be updated
        /// </summary>
        public bool needsUpdate;


        /// <summary>
        /// application type (32 or 64-bit)
        /// </summary>
        public ApplicationType type;
    } // class
}
