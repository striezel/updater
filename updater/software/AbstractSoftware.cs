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
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    abstract public class AbstractSoftware : ISoftware
    {
        /// <summary>
        /// NLog.Logger for AbstractSoftware class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(AbstractSoftware).FullName);


        /// <summary>
        /// default constructor
        /// </summary>
        /// <param name="automaticallyGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public AbstractSoftware(bool automaticallyGetNewer)
        {
            m_newerInfo = null;
            m_automaticallyGetNewer = automaticallyGetNewer;
            m_triedToGetNewer = false;
        }


        /// <summary>
        /// list of IDs to identify the software
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        abstract public string[] id();


        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        abstract public AvailableSoftware knownInfo();


        /// <summary>
        /// gets the information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public virtual AvailableSoftware info()
        {
            if (!m_automaticallyGetNewer)
                return knownInfo();

            if (m_newerInfo != null)
                return m_newerInfo;
            //If this instance already tried to get the newest info and failed
            // or does not implement search for newer, we fall back to the known
            // information.
            if (((m_newerInfo == null) && m_triedToGetNewer)
                || !implementsSearchForNewer())
                return knownInfo();

            //get newer information
            var temp = searchForNewer();
            m_triedToGetNewer = true;
            if (temp != null)
            {
                m_newerInfo = temp;
                return m_newerInfo;
            }
            logger.Warn("Search for newer information for " + knownInfo().Name + " failed!");
            //Search for newer info failed. Return default known info.
            return knownInfo();
        }


        /// <summary>
        /// set whether to automatically get new software information
        /// </summary>
        /// <param name="autoGetNew">new setting value</param>
        public void autoGetNewer(bool autoGetNew)
        {
            m_automaticallyGetNewer = autoGetNew;
        }


        /// <summary>
        /// whether or not the method searchForNewer() is implemented
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        abstract public bool implementsSearchForNewer();


        /// <summary>
        /// looks for newer versions of the software than the currently known version
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        abstract public AvailableSoftware searchForNewer();


        /// <summary>
        /// lists names of processes that might block an update, e.g. because
        /// the application cannot be update while it is running
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        abstract public List<string> blockerProcesses(DetectedSoftware detected);


        /// <summary>
        /// whether or not a separate process must be run before the update
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate proess returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        abstract public bool needsPreUpdateProcess(DetectedSoftware detected);


        /// <summary>
        /// returns a process that must be run before the update
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        abstract public List<Process> preUpdateProcess(DetectedSoftware detected);


        /// <summary>
        /// whether the detected software is older than the newest known software
        /// </summary>
        /// <param name="detected">the corresponding detected software</param>
        /// <returns>Returns true, if the detected software version is older
        /// than the newest software version, thus needing an update.
        /// Returns false, if no update is necessary.</returns>
        public virtual bool needsUpdate(DetectedSoftware detected)
        {
            //Simple version string comparison.
            return (string.Compare(detected.displayVersion, info().newestVersion, true) < 0);
        }


        /// <summary>
        /// checks whether the software is in the list of detected software
        /// </summary>
        /// <param name="detected">list of detected software on the system</param>
        /// <param name="autoGetNew">whether to automatically get new software information</param>
        /// <param name="result">query result where software will be added, if it is in the detection list</param>
        public virtual void detectionQuery(List<DetectedSoftware> detected, bool autoGetNew, List<QueryEntry> result)
        {
            var known = knownInfo();
            if (Environment.Is64BitOperatingSystem && !string.IsNullOrWhiteSpace(known.match64Bit))
            {
                Regex regularExp = new Regex(known.match64Bit, RegexOptions.IgnoreCase);
                int idx = detected.FindIndex(x => regularExp.IsMatch(x.displayName) && !string.IsNullOrWhiteSpace(x.displayVersion));
                if ((idx >= 0) && (detected[idx].appType == ApplicationType.Bit64))
                {
                    //found it
                    autoGetNewer(autoGetNew);
                    bool updatable = needsUpdate(detected[idx]);
                    result.Add(new QueryEntry(this, detected[idx], updatable, ApplicationType.Bit64));
                } //if match was found
            } //if 64 bit expression does exist and we are on a 64 bit system
            if (!string.IsNullOrWhiteSpace(known.match32Bit))
            {
                Regex regularExp = new Regex(known.match32Bit, RegexOptions.IgnoreCase);
                int idx = detected.FindIndex(x => regularExp.IsMatch(x.displayName) && !string.IsNullOrWhiteSpace(x.displayVersion));
                if ((idx >= 0) && (detected[idx].appType == ApplicationType.Bit32))
                {
                    //found it
                    autoGetNewer(autoGetNew);
                    bool updatable = needsUpdate(detected[idx]);
                    result.Add(new QueryEntry(this, detected[idx], updatable, ApplicationType.Bit32));
                } //if match was found
            } //if 32 bit expression does exist
        }


        /// <summary>
        /// whether to automatically try to get newer software
        /// </summary>
        private bool m_automaticallyGetNewer;


        /// <summary>
        /// newer software information, if present
        /// </summary>
        private AvailableSoftware m_newerInfo;


        /// <summary>
        /// whether there already was an attempt to get newer information
        /// </summary>
        private bool m_triedToGetNewer;
    } //class
} //namespace
