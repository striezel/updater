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
using System.IO;
using System.Net;
using updater_cli.data;

namespace updater_cli.operations
{
    public class Update : IOperation
    {
        /// <summary>
        /// NLog.Logger for Update class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Update).FullName);


        /// <summary>
        /// default timeout (in seconds) after which an update of a single
        /// application will be cancelled, if it is still in progress
        /// </summary>
        public const uint defaultTimeout = 1800; //1800 s = 30 min


        /// <summary>
        /// minimum timeout (in seconds) for an update of a single application
        /// </summary>
        /// <remarks>Ten seconds is too low for most updates, except for small
        /// updates / installers on solid state drives or similar fast drives.</remarks>
        public const uint minimumTimeout = 10;


        /// <summary>
        /// default constructor
        /// </summary>
        /// <param name="_autoGetNewer">whether to get newer software information, if possible</param>
        /// <param name="withAurora">Whether or not Firefox Developer Edition
        /// (aurora channel) shall be included, too. Default is false, because
        /// this increases time of the query by quite a bit (several seconds).</param>
        /// <param name="_timeout">maximum time in seconds per update process</param>
        /// <param name="_exclusion">list of software IDs that shall not be in the list</param>
        public Update(bool _autoGetNewer, bool withAurora, uint _timeout, List<string> _exclusion)
        {
            includeAurora = withAurora;
            autoGetNewer = _autoGetNewer;
            timeout = _timeout;
            exclusion = _exclusion;
        }
        
        
        /// <summary>
        /// performs software updates
        /// </summary>
        /// <param name="status">software status, as retrieved via SoftwareStatus.query()</param>
        /// <param name="timeoutPerUpdate">maximum time in seconds to wait per update</param>
        /// <returns>Returns the number of updated application in case of success.
        /// Returns a negative value equal to -1 - number of updated applications, if an error occurred.</returns>
        public static int update(List<QueryEntry> status, uint timeoutPerUpdate = defaultTimeout)
        {
            if (null == status)
                return -1;
            if (status.Count == 0)
            {
                logger.Info("No known software was found, so no update will be performed.");
                return -1;
            }
            //set some reasonable timeout, if necessary
            if (timeoutPerUpdate <= minimumTimeout)
            {
                timeoutPerUpdate = defaultTimeout;
            }

            int updatedApplications = 0;
            foreach (var entry in status)
            {
                if (!entry.needsUpdate)
                    continue;

                InstallInfo instInfo = null;
                switch (entry.type)
                {
                    
                    case ApplicationType.Bit32:
                        instInfo = entry.software.info().install32Bit;
                        break;
                    case ApplicationType.Bit64:
                        instInfo = entry.software.info().install64Bit;
                        break;
                    case ApplicationType.Unknown:
                        logger.Warn("Warning: Unknown application type detected for "
                            + entry.software.info().Name + "! Update will be skipped.");
                        continue;
                    default:
                        logger.Warn("Warning: Unknown application type detected for "
                            + entry.software.info().Name + "! Update will be aborted.");
                        return -1 - updatedApplications;
                } //switch

                //If no checksum is provided, we do not even try to download the file.
                if (!instInfo.hasChecksum())
                {
                    logger.Error("Error: No checksum for download of "
                        + entry.software.info().Name + "!");
                    logger.Error("Since installing unverified software can"
                        + " pose a security thread to your system, the update is cancelled.");
                    return -1 - updatedApplications;
                }

                //download file
                if (string.IsNullOrWhiteSpace(instInfo.downloadUrl))
                {
                    logger.Error("Error: No known download URL for " + entry.software.info().Name + "!");
                    return -1 - updatedApplications;
                }
                logger.Info("Downloading " + instInfo.downloadUrl + "...");
                string downloadedFile = download(instInfo.downloadUrl);
                if (string.IsNullOrWhiteSpace(downloadedFile))
                {
                    logger.Error("Error: Could not download installer from " + instInfo.downloadUrl + "!");
                    return -1 - updatedApplications;
                }

                //calculate checksum
                logger.Info("Calculating checksum of " + downloadedFile + " ...");
                string hash = utility.Checksum.calculate(downloadedFile, instInfo.algorithm);
                if (string.IsNullOrWhiteSpace(hash))
                {
                    logger.Error("Error: Could not calculate checksum of file " + downloadedFile + "!");
                    File.Delete(downloadedFile);
                    return -1 - updatedApplications;
                }
                if (!utility.Checksum.areEqual(hash, instInfo.checksum))
                {
                    logger.Error("Error: Checksum of file " + downloadedFile
                        + " is " + hash + ", but expected checksum is " + instInfo.checksum + "!");
                    File.Delete(downloadedFile);
                    return -1 - updatedApplications;
                }
                logger.Info("Info: Checksum of " + downloadedFile + " is correct.");

                //start update process
                try
                {
                    //preparational process needed?
                    if (entry.software.needsPreUpdateProcess(entry.detected))
                    {
                        var preProcs = entry.software.preUpdateProcess(entry.detected);
                        if (null == preProcs)
                        {
                            logger.Error("Error: Pre-update process for "
                                + entry.software.info().Name + " is null!");
                            return -1 - updatedApplications;
                        }

                        foreach (System.Diagnostics.Process preProc in preProcs)
                        {
                            logger.Info("Info: Starting pre-update task for "
                                + entry.software.info().Name + "...");
                            try
                            {
                                preProc.Start();
                                uint intervalCounter = 0;
                                do
                                {
                                    System.Threading.Thread.Sleep(1000);
                                    ++intervalCounter;
                                    if (preProc.HasExited)
                                    {
                                        logger.Info("Info: Pre-update process exited after "
                                            + intervalCounter.ToString() + " second(s) with code "
                                            + preProc.ExitCode.ToString() + ".");
                                        break;
                                    }
                                    //only wait up to timeoutPerUpdate seconds
                                } while (intervalCounter <= timeoutPerUpdate);
                                bool success = preProc.HasExited && (preProc.ExitCode == 0);
                                //Kill it, if it is not done yet.
                                if (!preProc.HasExited)
                                {
                                    logger.Error("Error: Killing pre-update process, because timeout has been reached.");
                                    preProc.Kill();
                                    return -1 - updatedApplications;
                                }
                                if (!success)
                                {
                                    logger.Error("Error: Could not perform pre-update task for "
                                        + entry.software.info().Name + ".");
                                    return -1 - updatedApplications;
                                }
                            } //try-c
                            catch (Exception ex)
                            {
                                logger.Error("Error: An exception occurred while running a pre-update tast for "
                                    + entry.software.info().Name + ": " + ex.Message);
                                return -1 - updatedApplications;
                            }
                        } //foreach
                    } //if preparational process is needed

                    var proc = instInfo.createInstallProccess(downloadedFile, entry.detected);
                    if (null == proc)
                    {
                        //error while creating install process - should never happen
                        logger.Error("Error: Could not create install process for "
                            + entry.software.info().Name + "!");
                        return -1 - updatedApplications;
                    }

                    try
                    {
                        logger.Info("Info: Starting update of " + entry.software.info().Name + "...");
                        logger.Debug("Command line: " + proc.StartInfo.FileName + " " + proc.StartInfo.Arguments);
                        bool startedNew = proc.Start();
                        uint intervalCounter = 0;
                        do
                        {
                            System.Threading.Thread.Sleep(1000);
                            ++intervalCounter;
                            if (proc.HasExited)
                            {
                                logger.Info("Info: Update process exited after "
                                    + intervalCounter.ToString() + " second(s) with code "
                                    + proc.ExitCode.ToString() + ".");
                                break;
                            }
                            //only wait up to timeoutPerUpdate seconds
                        } while (intervalCounter <= timeoutPerUpdate);
                        // Update was successful, if process has exited already,
                        // i.e. there was no timeout.
                        // Additionally, the exit code must be zero.
                        // However, for MSI processes the exit code 3010 means
                        // the the update succeeded, but a reboot is required.
                        bool success = proc.HasExited
                            && ((proc.ExitCode == 0)
                            || ((proc.ExitCode == InstallInfoMsi.successRebootRequired) && (instInfo is InstallInfoMsi)));
                        //Kill it, if it is not done yet.
                        if (!proc.HasExited)
                        {
                            logger.Warn("Warning: Killing update process, because timeout has been reached.");
                            proc.Kill();
                        }
                        if (success)
                        {
                            logger.Info("Info: Update of " + entry.software.info().Name + " was successful.");
                            ++updatedApplications;
                            if ((instInfo is InstallInfoMsi) && (proc.ExitCode == InstallInfoMsi.successRebootRequired))
                            {
                                logger.Warn("Warning: A reboot is required to"
                                    +" finish the update of " + entry.software.info().Name + ".");
                            } //if MSI installer requires reboot
                        } //if success
                        else
                        {
                            logger.Error("Error: Could not update " + entry.software.info().Name + ".");
                            return -1 - updatedApplications;
                        }
                    } //try-c
                    catch (Exception ex)
                    {
                        logger.Error("Error: Exception occurred while updating "
                            + entry.software.info().Name + ": " + ex.Message);
                        return -1 - updatedApplications;
                    } //try-catch
                } //try-fin
                finally
                {
                    try
                    {
                        File.Delete(downloadedFile);
                    }
                    catch (Exception ex)
                    {
                        logger.Error("Error: Could not delete installer file "
                            + downloadedFile + " after update: " + ex.Message);
                    }
                } //try-finally
            } //foreach

            return updatedApplications;
        }


        /// <summary>
        /// downloads a given file to the local cache directory
        /// </summary>
        /// <param name="url">URL of the file</param>
        /// <returns>Returns path of the local file, if successful.
        /// Returns null, if an error occurred.</returns>
        private static string download(string url)
        {
            if (string.IsNullOrWhiteSpace(url))
                return null;

            string basename = null;
            try
            {
                Uri uri = new Uri(url);
                int segCount = uri.Segments.Length;
                if (!string.IsNullOrWhiteSpace(uri.Segments[segCount-1]))
                    basename = Path.GetFileName(uri.LocalPath);
            }
            catch (Exception)
            {
                //ignore
            }
            if (string.IsNullOrWhiteSpace(basename))
                basename = Path.GetRandomFileName() + ".exe";
            string cacheDirectory = downloadCacheDirectory();
            if (null == cacheDirectory)
                return null;
            if (!Directory.Exists(cacheDirectory))
            {
                try
                {
                    Directory.CreateDirectory(cacheDirectory);
                }
                catch (Exception ex)
                {
                    logger.Error("Error while creating cache directory: " + ex.Message);
                    return null;
                }
            } //if
            string localFile = Path.Combine(cacheDirectory, basename);
            using (WebClient wc = new WebClient())
            {
                try
                {
                    wc.DownloadFile(url, localFile);
                }
                catch (Exception ex)
                {
                    logger.Error("An error occurred while downloading the file "
                        + url + ": " + ex.Message);
                    wc.Dispose();
                    return null;
                }
            } //using
            return localFile;
        }


        /// <summary>
        /// get the path of the download cache directory
        /// </summary>
        /// <returns>Returns path of the download cache directory on success.
        /// Returns null, if an error occurred.</returns>
        private static string downloadCacheDirectory()
        {
            string path = null;
            try
            {
                path = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                if (string.IsNullOrWhiteSpace(path))
                    path = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                if (string.IsNullOrWhiteSpace(path))
                    path = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            }
            catch (Exception)
            {
                //ignore
            }
            if (!string.IsNullOrWhiteSpace(path))
                return Path.Combine(path, ".updaterCache");
            return null;
        }


        /// <summary>
        /// Flag that indicates whether or not Firefox Developer Edition
        /// (aurora channel) shall be included, too. Default is false, because
        /// this increases time of the query by quite a bit (several seconds).
        /// </summary>
        private bool includeAurora;


        /// <summary>
        /// whether to get newer software information automatically
        /// </summary>
        private bool autoGetNewer;


        /// <summary>
        /// maximum time in seconds per update process
        /// </summary>
        private uint timeout;


        /// <summary>
        /// list of software IDs that shall not be updated
        /// </summary>
        private List<string> exclusion;


        public int perform()
        {
            var query = SoftwareStatus.query(autoGetNewer, includeAurora, exclusion);
            int result = update(query, timeout);
            if (result < 0)
            {
                logger.Error("At least one error occurred during the update.");
                if (result < -1)
                {
                    logger.Info("However, " + (-result - 1).ToString() + " applications were updated.");
                }
                return result;
            }
            if (result == 1)
                logger.Info("One application was updated.");
            else if (result > 1)
                logger.Info(result.ToString() + " applications were updated.");
            else if (result == 0)
                logger.Info("No applications were updated.");
            return 0;
        }
    } //class
} //namespace
