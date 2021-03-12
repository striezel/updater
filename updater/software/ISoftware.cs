/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2020  Dirk Stolle

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

using System.Collections.Generic;
using System.Diagnostics;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// interface to provide information for various softwares
    /// </summary>
    public interface ISoftware
    {
        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        AvailableSoftware info();


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        string[] id();


        /// <summary>
        /// Sets whether to automatically get new software information.
        /// </summary>
        /// <param name="autoGetNew">new setting value</param>
        void autoGetNewer(bool autoGetNew);


        /// <summary>
        /// Determines whether or not the method searchForNewer() is implemented.
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        bool implementsSearchForNewer();


        /// <summary>
        /// Looks for newer versions of the software than the currently known version.
        /// </summary>
        /// <remarks>This is where the useful stuff happens.</remarks>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        AvailableSoftware searchForNewer();


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        List<string> blockerProcesses(DetectedSoftware detected);


        /// <summary>
        /// Determines whether or not a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate process returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        bool needsPreUpdateProcess(DetectedSoftware detected);


        /// <summary>
        /// Returns a list of processes that must be run before the update.
        /// This may return an empty list, if no processes need to be run
        /// before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        List<Process> preUpdateProcess(DetectedSoftware detected);


        /// <summary>
        /// Checks whether the detected software is older than the newest known software.
        /// </summary>
        /// <param name="detected">the corresponding detected software</param>
        /// <returns>Returns true, if the detected software version is older
        /// than the newest software version, thus needing an update.
        /// Returns false, if no update is necessary.</returns>
        bool needsUpdate(DetectedSoftware detected);


        /// <summary>
        /// Checks whether the software is in the list of detected software.
        /// </summary>
        /// <param name="detected">list of detected software on the system</param>
        /// <param name="autoGetNew">whether to automatically get new software information</param>
        /// <param name="result">query result where software will be added, if it is in the detection list</param>
        void detectionQuery(List<DetectedSoftware> detected, bool autoGetNew, List<QueryEntry> result);
    } // interface
} // namespace
