/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020 - 2026  Dirk Stolle

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
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Firefox class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.TryGetValue(languageCode, out checksum32Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/156.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "066b52394e6367ae62a9a153439992f3cd2539f7b30e650966c111b6a59ba0fa04c5fe189f52a74ee35e7d5b04a3cc00016b880dc67e8c2b369483e51b6d0e56" },
                { "af", "4435ede246f0fcf35e9accd153eeaa9b26e6c54c167bf5dc1b9ff218f6a3d80340a99ce55a0e65209ba89602ba3fbd89c40bbb43003a42cf60899b32fa30cb86" },
                { "an", "caf65961e65117d32aa05be370c72f568adb85c73058a87be250d7d620a6420afcb273f86b1473f0372e2361577bf2762ddfeab2d3bdc8d9bdb54b4e4836eec5" },
                { "ar", "dab21f95ac8ae1d5e2635b7965e1badfa0fa3aa9b3438e01580e3aba40e4e959801a053c0a970bbfaa74defed522b459a390333836ebbbb0ec6be1378cd409c1" },
                { "ast", "97f10270509051625cc1fa83d93ee4b7fa5c9c2a20b957aad915f77397e46dc7d698063d67312d769a0165cea8b1edb6c1a62e044a6e57ed0bc451f7a85c8f6c" },
                { "az", "75dc82a7f59b06b58ae3ea7452a09683f38c99e80f529c12710574e82fde529666531d8a0f33d1cc3d08fb9e3f301e546811ad62e7eced166809d4891ed5de76" },
                { "be", "fcdd628d5eec769fe60940cc2b038b05b77ebbd64b1fa7327c0731dfa72e7ebbbdfa76edf6e7616b16c2f87cae9489cc84b82a0064d355abf4010cc8ec165637" },
                { "bg", "3985c63751a048d242e5273852ec48fee0f955a3ebeac98a54ef0bce33405a2b92bbb95ddea1361eaa4402082966068736f969514848cec7180e61563656452f" },
                { "bn", "27d170d204a10e61eeff7441f4e0b8b40edee5b8f37b1de4687ecf43d944374b51aed03eb78ba761ee3363e3184e06b229e0b1335635a56eb5f84902fb5df362" },
                { "br", "5b3d8e8e9de6c738e94ff81a89d346657ea2f4a78a8f49fccd3e1c9bb071275e002ff85e57329df1194f71d9fea072e7caa6a820fa56908e944812805f0c5aca" },
                { "bs", "efdd8f99e205940d27f13486dad0bbceff72406d687d9485c17cb67c21b085518d633ce9acc596d58d3bf11097ceecf37dd776f56018c2a9f6d041d468395daf" },
                { "ca", "af7feadc868c8d00e489ac24fb58a8462d6231e410414cf0fd9d202b3cd54a980d5e1905cc642c7b0a5fe828df009a9e876ff4915c23036d4f43be825ff9a63c" },
                { "cak", "49b1d5688c762c6f45b8b384f65660811020b45b3a5a3415d252d4b1d88c4dc479fb547affb085e23fcfe0f4a3d42308f8f610f2e5fb19d468572874c3bc2eb7" },
                { "cs", "7891c9ba1e39c95961cace9cf765e893652343594755c7253116eb99026a2b7eea6eb5262dc9e90f232c0ffec5f9bdbf7453024a1b2434839a8fdf464921fa94" },
                { "cy", "39ce6cdfdff80d7a242f80e15d711de2edf3d57f74765624ac77512631d1f81d643dcf029a705c186437cbc9c40d9d9aea4fb02aa1b2c2cde087359779cb8b9e" },
                { "da", "0c018ea2acc60b5ddf691b3bb0b9b1108b70ba2293a7aa6e0b2f6b2267fa6f565ba17831ca68df9b3ca3c2533fb0a99fdaae91f3718f65b193c25f36908edb73" },
                { "de", "69a603028ac8dc4ce7482ce14c655b3c78973a0a8869fe2813bfd17d520c2096026e1182ca6e381cb52182ccc56c66f9308b305f0d8463278aaad7e7e8a9329e" },
                { "dsb", "95b2946326b76036966a0185fa3c7df0b7a270e97caa7d9446fc45b32ddc3edb3916da435543b8f9f612859adbad9ecb11a1ab6c78c23011440220ceb4f2c095" },
                { "el", "2b2b41f28b74a731d4f5770a6ced7a32f6d807d3b419ea3570f236d4a67a5657fe06aaadb182a607cb0f66142c3e64eba2e43e5a154c08b01c375d9cb43d8984" },
                { "en-CA", "d6c06e631a45beffd615fe44ee46cdfe0df47f665b165522ec7db5ca37bbec1877fe9e7ecddd346597b884f80a208ef74a695147fc1a0d7736a4111b4572985c" },
                { "en-GB", "1ae0aa4df1ebd659e099f066d191d9ebdf6197584d0e18bb9eb66b9c0eeaffcb215472405876615941194be511d8c1d122addf122249fd354b415c7ef53056bd" },
                { "en-US", "2dc2803d31a4aed8798641f1e36c640a6df978ed3f873b4fd8f847a436b05cf4ad9a6bfc220daf5ce97e56e7ee76d38a0a867063e90e10ad4020e82e07a0a639" },
                { "eo", "3cdba72f196385bdb8158da0a0f788c492e67cd82052e16e9d41df058a96e31d59f01c36f4b5462d64e37ea2c96af8701048880431b5e524fd2dc8b793281b12" },
                { "es-AR", "c6ac3e9cd2aedc219ecdc6fe0eb01456a3b78d4faf6253e71c567cd425cef7aa434041617038960a7b51384b4a99f74a27efd282487e2052af38ba69001b9989" },
                { "es-CL", "f240ac3663a44c1a513fe1226a6ccbd7c66e50c2c027de2116ff26514669b6874e0213445ba52a062740408ff1075c615c589ab2dffc4f299ffd40631535acff" },
                { "es-ES", "3e1aea783f6721199149a23243cab24ccf1a5f286e35d0649db64eb27df8bcd767bf35104bb75fe38bccdfb337c043372f25c3b880979a98f4e0f853d4014529" },
                { "es-MX", "4719ecb9bc6415b8e85ab857b71ea9eb0037967be6a60c2e117e9a6feeae21dc4bb8ffbf86aa8279cea347c9c998a9f657e1af57920ebdab32bd900ab7089acc" },
                { "et", "f52ffc7a514ffcb3f39b9f20e928f1ffba57b99d0e3abd024be348e9079e95bb9df514566d5eb64b14653292f4c5a35c46cf2190a56430eec34a02bebd9c22b7" },
                { "eu", "584b42c2a92897426a84e76e0bdf84d4802ef0475bd50501e6b32ae35b973cc52818cd1c4304127b0c24a1021e197c0533595f8aa5f32e7f0ddb4ed3ed41f4da" },
                { "fa", "96f2a439a402f5561a78dd518f9bcfe9a2b555909a0b4913f875ac3cecddba8651adeec089a91e4d3557bf116a72d14563804a92c031dc7bb142f8eeb31cdc4d" },
                { "ff", "25ccc2005d515501ee6f301caa0b67f64a11b50c987d0228e8d3a84ba40491ce1950a013d3d9448d0255e0439535ea200318dea71b82dca6f0a1b1f17f9d1503" },
                { "fi", "019ec6c3df6bef9de1c558bdead63fa14b0baa1cfe1236a069cf0614ce7c2d3874e2954fc92fc1a704eb1c1374e797c2d64b9566023c68b46aad19b8dd65955a" },
                { "fr", "23ab230ae67ef446060b85cda6669d720ef4e3cb51b8e86dcc287d8a6a462fab0733137468a0e123d0d3ba1e7d27cd71929bd014446476b99c8ed88821f2a1e2" },
                { "fur", "af1f1d9bc8c3971a902f0ed2b4b47796867590b51c4a9925468fd28957d9da40562c3e2dd4233b5d8ce2983e05d98f0e8cab9a3346d75a1a8df04e60e6fbb884" },
                { "fy-NL", "cd894a396b8487ccf11d314f77cacba8cd343dc7505261e64a3edd51856b77b9f47b9c543fe2784fe5490d148ae2f92ecdf2e429a99c33a6346929879b348115" },
                { "ga-IE", "b1cfbb26e0910610b6b33e2ede0789326b66751c431e7f0bfdf8534ddac4aa4288c6a62693cd2d3c2ec61861f0bb91ff8e2d92f3c979abf4a13210dca0a8554f" },
                { "gd", "c569c13335ea7bd8fe046a9ee6974f54ff9676be758b87f4aec0966ce675104e3f630c48c1bb33918f43f1928041e6a43b5b101a536986239c75513b9093cf37" },
                { "gl", "cbd7514a5e760dced7f78e582c54971f4403dd538843413bc3a70334fda8fc99bb7eb84f4cf4668f03497ad311da53eb24b8760e8de519760462aa49d0c81cfb" },
                { "gn", "80d8066ab07184a5cdd7250aa7e47e7bd1e6a5b9dc2e08703f4d103667704da2a8a228544097f0b7c450972d1ea36039b31f1eb4d08b7c9109212bbd82490cf9" },
                { "gu-IN", "5e5875fc00a0534cc56723e3797494bab8ef20f6ec7849dcb3259c4a583fa72617f1138d3213f8fbcc78bab15f7feb8d5a1ae2a2b7e2074a5d68663dd3a4719a" },
                { "he", "071cffd325e7f0c11caf45e62817e0bf28e7dadc85f13838a1729c44b778a9bd4db5b2327aedf58eebc4a82fa6e8164d4826a91b2658f975486f0a3d2d518a11" },
                { "hi-IN", "63c00617cf909883aef59d76f775b782b9224519525efd7a875b44a1440090932517b87f892d1292d1fd6ae931cc4201e2055186f5bb580776b249bbd21c3517" },
                { "hr", "1b478dec20450f9b8c60fb63485e6f7b9afb2b7d94cb5a1615d00c6b90a081683eece40a13de96e2a37926d119f95bf9eea4cfae96631b702035a458c78ca547" },
                { "hsb", "4e0a7241bde2aef5098c9a30485c99785b38f79f7691d71e18d02a319f73922eee86ac7e8d4260f0a45fa10bdc2d5782e7343b35195a6e8967e994c8d684dbc2" },
                { "hu", "14ed5cebcdbea5025ff1ffe49b329fb212bf7dc35890f646c3e2a78bc5dd74721c89686342e946a91662d7f3d88a8b98bf84eb37ea094a5c60a5034ee5724586" },
                { "hy-AM", "f57a130c99b07a24b7d6bcbcedef1cfa15380dfa440f4505d87220a552355f64aebe5bcf59fadaa603eb3b0ce91096378cdbbd4b367d6e99bdf02f12a5cbf5ac" },
                { "ia", "5e99d726409d7a82e99a5f9f2ae3a4d5e6b8f44e7cf5946eab1bb618f89e38b0c0b4568c503b20e93facb903777a8bcc0cacf9073d0f6bd2f2167ea0b2e17970" },
                { "id", "da8f5041feb14ae6608f8728b004c57a6de02c768a1eac4e615e101e7c90c620a7caca392c9e70d5aadf92ee6a731d1e94d5fc85362159f1a4080a58af3db007" },
                { "is", "92b78dda5f40ae5a8e25406dcd456398d7fd0687d9968714479bba32116ebffc8e0265d342df79fce499e616fe0bed79ea7a0dc7c3ccb5f54afb9c1172242600" },
                { "it", "d4d77efead716df52ad91163dafe0541125025da837336ccb1c871bb9574a359fcfed2848e27de53c2b9c8b4f10dbc4a2253b5d665c16f39b625fa2dba14a74c" },
                { "ja", "3183a1291baaf31da556b05454de159baf027f8ba958397689b455cb6d84c7f15fa022c4cc430b1a3867a9201139f79d176c9625159e86b6a38d74ed08d67c44" },
                { "ka", "10269613ce78ef928706a8d898dfd3f8ebeeb0bc42564aac872d370fb70971bdfd77fc0cf03d9020cee66213a59cdb949eaa73458cb80a9e6e78856428675123" },
                { "kab", "243b9779c86d02779b607e7ce41e90d759eac1dea2c2b4e2e7a4b2e83f31dcf2f95c9ed76ca0d1d2c6994ee23a4b6d982a1cbfea5ca78b02a9523cefcb9d0c17" },
                { "kk", "85337d90f792e546fead084d4e89075f2d633c1589d304c420ad7a9bbd7c8e3b1784789369975042100126fcc299847edaf60c6df3eba9b87622b838df722de6" },
                { "km", "3c4f7222c55207d1a03ef2526921f01822b4106167202ef8823d9a9b1157e6c874ff37c53f92d4064983309244961cd73c7e6c2ed80ab1f23bb9ce5b28c82a03" },
                { "kn", "f7c3446d47eebe8d474d6487acecaec3914ad0b6e870e50e69df921589abfff198bf6abbe395b97c02aff62d87b1e70a392b8904fe89211e676da3b055e1abf7" },
                { "ko", "c266e53caf28cb65f56ab3077aa486eb3d9ee4b7c223008ddef96d2670930f39d9b6167542f7cb725b4895fd09b51d34d256ccb1bc4e313b2d3cb2abb7726521" },
                { "lij", "d34946e4c3f28b592e517b2a0635c59d4aa0440e2e23c629b2db6d1640e757ba5f161a457f5e29ce4c7dd83463dbe944c6addf6ecb1b9254621bdebd8bcc8197" },
                { "lt", "e64d4df57e147afbc8caa62f1024c69fbfd78d353da7988a18907b25be5df0cf0f03c5c6c36b05079ae1af8f1ae8e4f962743fbcc6fae5e5c26437e1ad691dfa" },
                { "lv", "90a82c3c9b35fc41ccb84fcbd41aff08678351ff9a8589ea8d40879d6efb6e84b681c53ffc4e7940663165decb571abc155e35ea57d1fb11b75b50fd3d397987" },
                { "mk", "81ff936653e7466aba3d86cb91d7a067e477667f7a47556606b4a6eaf681b2b59d5ed4dda0d77943d347b3a307f646b2ce9cd9889e58ebfc69d9529c16c50d16" },
                { "mr", "a02166b306cd63027965b9927bb13df99b725d93497c2c8dfb7a2f38b2d9e4b2051834120d004595557c517c5f3014e146ce5525067ce88777f46fa15d9761f3" },
                { "ms", "3ef4b4d9657d2015bde299691e94c41fe97d3ffaa01c4bf5b3668a34a5a9bb7680210ace3de88f3c74bdbb0f240872a7467585ce3133e2e661bf3d24adc665ed" },
                { "my", "157b20b90da1160aaa1cc88e9645e63e875239e38fafdbf2eb7f7ae2c0f6082d91e498333622ccb09807143f2abb416ea3359b7205f50d697d272b1d8a2361d5" },
                { "nb-NO", "e4abd7cf77b1b9a0423d7f76a6dfd2e12759a3a43b23298c78da3c2852d774ddc7d53e1ed39bced68691b94094fdc839c4c95e3cbbbdc30800faf0f28bb9ca47" },
                { "ne-NP", "f1f0aba5cc06cac892ce1790cdf7f037ab98bcec268cea5cde180c5f9583f62706173ae8d7ebbeb3fd865957b7a3f99b0580a689c43e670cfcbbba158f9f224d" },
                { "nl", "d1546fb59debb0be4f677faf5ac832277fa288faf388ed2bf550749ab387f84e3ad0361658b4ab2dde729296a7b08b0c9fcc61b15d165990732590a927837b08" },
                { "nn-NO", "f3d43fba6b43c9316a1198d10d806aa15323f7d8348b5704610bd65f969ee8f7cfda7f9044c2011165d5aeff9512c775a5e3638cbda746527635d327901d2a16" },
                { "oc", "8a5fa653850d793f791d1cb218e949d61ccc36fb36653a4d2e25284e2f8f23c0876f39b6af4e8b7c3f7084a49b15dc09b216243ad2fb786a6b609e2170f54bb6" },
                { "pa-IN", "edef1ddb0f62edb351cce94daf23b85f9ef9f76ac61105fa89f1c5f9853fb1bc7e839fd5020e2fb56a9fcdef4262f5377136307ff77723e64e8336932d5885f4" },
                { "pl", "fc4a28c1f927b448d61165de13d87d1476e28e61871d0233d2576b8e968fcac12b9e5018da26742957720a28e152645624da8962345e80af7912a868305d27e2" },
                { "pt-BR", "f12d12e9b95469eb72b9ac688db426955ad94f2eb90e9e3d20b23f7e959f0957e119162a81de736d0404470c33f7eddc5ebbc9dadc33ce866d683e4ff3f89702" },
                { "pt-PT", "da0aaeeb892a61e46afafdd2c29534ea69af1cecae1085fb856ab3f3c065b5c7548f8b5242f392498d1a784a0c8ca7f393ae32978e2a20fade0f4d23e2d8c8f2" },
                { "rm", "749a13c622f3de9c54b9de70a7592c52fad5623bd023dbe8692ce2125cf8497f340a1d1a58d5a59adac23065ccc4827b23548533d117b1d24fd509de1f55be9d" },
                { "ro", "59fd012dabf367b19cfaab5decb6a4c973c701c55073dc93acbb6fbfc7de256535d6acb33c3de1e62179fe4891da7d68697be57b21db86650996f17e727df8ac" },
                { "ru", "eb42949f667bc93cc0592364a9a761380791ff84ed96303fc126e89b705c93de61ab683de857906d589f55e101c14a2ce7a0016271c0b35a7dc8028eb3b97dae" },
                { "sat", "b9dfbcdd5a3fa7ae2531e7d6330174f6b19c6e7fa464dbce933496892292c8d5bd417c806327c7017e9a92a30953c377595c84167b98cb1cba8d568ba1860c23" },
                { "sc", "57f905ac29bb7f7476c7d48da0a6561331163565cfd739f26be7ef15b1d9ff81df0d464457825c94131f812f61ecae05bb2061ea9a56ac7a328047b81812d6d6" },
                { "sco", "8211b90f52e9b5cc2236754c162a91c24d31ebf8e72db11015abe5e3d235be9eb1f90aed2598968da6873534320f1c2caa099fcfbead9ca86be7c3f880ce54f0" },
                { "si", "7dd51b800a54066b55e661d2853151df291c9c635b00402c51740cac3845b6d67d07a6b7217b58b57cdf10b7f7b66728a4491b1b14dfa80f6deca3de9034b235" },
                { "sk", "80341582e3e80caef6d677dd7f284e1ba6452aedef16863c26c422272c28a8f18aec8874ca3e7f3dbc75c7c4558734770774148cce02176fe4040b4752f073ac" },
                { "skr", "9ce4ae56bd1d50772baecea695f0c8a9aed5f2c8fa1392763a194135a018692806a8251d29fa38e92318af3dfe955123fc65dcc2713f32679f6ec43921e83fb6" },
                { "sl", "dc15aab6c4a9f5a5ae50f58c201fc781f936208314b91c772af280c83e1bbeb711de6d8ebc097fe68909a011e0aa5e547838bfd47d78bd341cae263c7bf07407" },
                { "son", "7e4c2a048390ed33a76dea1359d601217f172f95fc3b9e586b929ba8c46073d481149ca6209e8acf118f8163bc93b1052025ff6fb6020923f6c37d749e6e6c3d" },
                { "sq", "b2477ea47d5c33c0f7b49d6ba16d885fd327569a83f8f6c1e7339d23e2f9fabe998643192e52ebda1558bf7874929fb8fe26e7ed79237710f34a3a5c6c75ed2d" },
                { "sr", "f22fdcdaf0914686d61a3dce273247e20e6b33e09b883d3e8227defec708d96d742553499b51c0212018598bca028b8777d60df9a37338cfb2d86013df6f3574" },
                { "sv-SE", "7bfeaef082afebd6c08a906d8f7c09faceda0ee829cc6a29e07cd050b16e106b4ec7877ec3be34f1f6b111ee9c0fa8279d8fcbd9efd1b0e3f3f885a4b844738c" },
                { "szl", "6a449cbda8822607155bc7897c60d44cac6b9e3d2887f50e2973b2d46091911cb614566df3f21a01beed225768b20474d2e231564241db75801250fd0ab2655a" },
                { "ta", "8ff64f7b5a4603a964181c4a0b6882978c1299469b90627f3971770bc602e87b4739a1a6cf35867f10e358c050bd388beb140824fac29591b2e71668885e1ff0" },
                { "te", "e8b6e4aa83d60811acf485452bf641e96ad12aa7fad8d9ab681942aad70399ff608399c481888b8e51316744eed548c75c8f21519d2fbcc8c7f079c70c784869" },
                { "tg", "dc0d1bd9b173c2a1065d935bd6724636357025cce20e9efe3660b9675499ddd6226d47840776a2fd9678520983282d23541e7103ef514a84df91a501c090f391" },
                { "th", "0560eea3fcd2f2194afd9cdf5e29a695aafe017c72cbf12b5864480989dccf64bcae455ed1737d9a5027b9bd7692c3c87955a421fb7953ae9804d6aacd2c4306" },
                { "tl", "5d416d701e3753ca76b0232765fdf2771bcb15a0c040b92206360eda150bad3b4f17242e4cd797c2fe245062d80a5c9aee4046ab648ea1e3d7377cb477f28110" },
                { "tr", "e66a67616c23a94a25af47add00257b0efbb216e8a43bf93515234746d956859e3043713fc56c63cfbd78e1f0d5b28f446f25bf99235c5df4a5485bd9fc6aaad" },
                { "trs", "e3696ad66ab507fdc5b07b9d34740722b85d8eb582bd4607789715bca1cc741b26defea42a9db65b49ef52aa3cf0af440f1f447e014cfe567dc286f5fa636a51" },
                { "uk", "a5331bca1f0cfbd210365510b786ae7bd5c537e93eb3c6cb624ff63002113cde0ee0f8fb011b377aca85b243d171672fc4972b07d7134db32927a2c89e85c044" },
                { "ur", "de030ac1784a69a424558486b61705f4b1c2a8211921ce9f869cb5b5806bc0b9775566c07375f8cb78af686e7aeb1f2275cf335392e783f99c16095aee034e94" },
                { "uz", "c849b1dbdd18159c35a94b30a03c9073577132b583e4a82a198dc220152ed33ae861ef8b67c12b66f02b5f7dbeb75f8953daf3a1c491dc2c102baeb4505e3883" },
                { "vi", "36bd7a0aa88d6573ed68a57d20322bb835a49a79ae752123acc1185d81d1e76d5842053332533ca13fdc3b36b61d8cab52b106044abf392bf47e140d144e5641" },
                { "xh", "74495b292c648f3811ce27f013eebccad540f2b35799972e2e203a24392f09f0aa6763d1ff2fa258c952e1012e5a699e80718cd6d2c6c9770cc99c68a5579bd4" },
                { "zh-CN", "431ea90ea34db79dae9e01b9c53ef220bd1e84c9c64de49bcda33de94a8bb6efc9cfd69bc0a8f413d7da72a78556face32b2c30d2a1e9bbc1675d76e7c26c849" },
                { "zh-TW", "d67ad6d537a9444b785157588492d1948ef549c39a6176f8bc4c461453e626c2b9f86dd41a4263f62a026e13e683c49ee0b31bc30ec90e3eacac9c1a90d040dd" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/156.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "b683d997ebe43968d50cb60cc609bb6850dcbaf96e2604a75404a38c6c387504943a90921e431f3a82510ab815505fbb1a7ac639992b7d1a643099f3d7ba1468" },
                { "af", "c9567715e6798e26ca072c7db42a94c058e1f393a57f83c3ae3991085d677caf61c36c7fee8c3710fde9d7066633a7dea5665a4a68e08d6f37fcb2e983299c50" },
                { "an", "2318cfabe5019684131b8cbc6e23f59c0625d5551a94cfbf78aa3a3117cc58bd97455b861e11f8ebc6eefb1a5cafb1cb710097a780ac532dbb707f3ebbfb231e" },
                { "ar", "f7908c8bbc8daf0dde75885abad5bf82401368eb8ef9435d60d1145a70b11ac76214f88cc5be7532a7e4b73a66a9a3daf4b0ff9b39d47d946c469f71d6ce5ad6" },
                { "ast", "7c56d4ba18a7696967dd5c1112022680c109c83b4015d1f580ed5202d0a7879cbe07b86442f6134edb06973a2ce50f52dedacc7ccd4da3a16f43b16d2a2507be" },
                { "az", "d80875e79b4b5a1684e2c021b3e3208a87a3c5323c41cfd54724f08d34c824675ae9c8ec6ffe51dcd919c3f81d2d46bb90d807b46c209e1c43eed1b3428f1f66" },
                { "be", "800be77142fcbcec2e4bdb7a36e49369331253acbc870488e28f07a44b3eb066ef52f42e781a53bcf475a3a9838fe60838d102694a5d94981bde4bd8b675b60b" },
                { "bg", "7173053da1eaed6295bbd7ccdd6b63197069ca036d9f4cb8c3182c7435b47eb30838b421716dbfe6dbddb34f375ee50503b17d4aae1f14307c4357cce9320c16" },
                { "bn", "93fcfcaea45d8418da5ac2e13d0aa923d045f62504342b3132b8016658f73bdd704b05ba6378bc1cab39da33def23b546476c81c6f09e2120cbb78221d4e0e01" },
                { "br", "5358b1a56b5e92e5312ee159c0477a5f3e98fba8369eb7912b2e4fce76df3bcac1947442caaf7dca5ecf65e973c350c7dc6a38b11b54b1957287daac522f7859" },
                { "bs", "802770a70526b16529d3894b6164ab2c32135e4a9ff554dd8f007bfed39f3f67e6e3da4c2f1fe8a510ffd1246e4e490abe2e325540cf2529c5cb336929544b2f" },
                { "ca", "a3ab903b428cc263466fff5b09a2d0035ffc06d193d7fe792e0afd85f13d0aa6b0272762216d31912a29eed09c7d00962b624836a04512b537c1e88bf1100344" },
                { "cak", "ba9b73062d0e136b7d6d87daea2d349f5dd669bd77ad4a7a441caccd7925c0451798689ebc583e5297cdecc4dfbcb77dda6ac3a38671550f55f634614ccd5661" },
                { "cs", "0c6cf19eff5ab79bafc32b115ddcf4fa48572d3b8b90efe917cf0b7d7aa150b5b1fdb2a0989bc7387ba3eae74c2d85fca44ccd2b56b169515308754bea0fc610" },
                { "cy", "3c7ab447f9b2ac24574ef98af4b32f65bd6b4accdc0de54c77f31b8394626c42c70cfbe418cd1fe644db7ad707d72cfd562355272829fd01c8640a7cdbde4966" },
                { "da", "c19023a10ccf84c76a13e96d044fa39b478b0e7c33b8097c2fb1ebb25384d395496f2fdde5721b0fcc1a8e8bab1e15089afd11484b9729bb58c52d3f9be9293e" },
                { "de", "5612f4278bd6084d18866c226b23e1928e4f3e25af99bafc5ea5902815b254187ac74a357683c28c48ef73745d523287516258dfe62525e39a177ca78f8064d4" },
                { "dsb", "35c1d522f5bfd8be1528de925757e0eefe5fc5e82f351f6df7926da798642de6f69f7fa26cbdcc0aa95a778df37749665b52392dacf99f1ec13b4ea0d456a594" },
                { "el", "dbc99e4959ddeffe6ad31ce719e51ded84d43ec4dc99f007d4cf60c2ad6d555eb138c4c1c2f6e2ba9da8d3686e9e54f50bf60a6ecfe2f3a1c5b248d3cbd67d6e" },
                { "en-CA", "0029f0ea6447484fb0f28a9886cf76ec2aec41934bb2f925548b896c1e50c1c839a8e64ddf88974a1b8c873775f651cb5d99beb193dc0a4b652e5a921e1ab36f" },
                { "en-GB", "ff0b103575ebbca63e4fcc2e928decf1be3047f807801e23fb5c7fd0246d5cd74f5d2ef647624c3556b1f1171e344ddb512f31c8b13b51688458c0c2eb0741db" },
                { "en-US", "f4b0aa38600935b1e9cdec76a70da40ecbc2f37e0058f2ca3e9daa3077bed8e7aca8e39fbd8df6763291a3f2a541bb1f2629570ba5e0fb646156cf50497f11b3" },
                { "eo", "d365e52a6e887d5d55c0c16bda39ba4c59f5795cbcf339ccd9e77424e972f35ba3f75b8f7ea09bc8c5ea0dfb2968bb06526c7cd81c35be69dd647fc26cb1d37f" },
                { "es-AR", "03169ac4cdf788d3d0a2a96d8dffb2a13964cc18e490b9f3299e95b1b9cbb50a75bea76d51978363b32049169aa7e36bc1a294db2e13accc4e1761d125163e4a" },
                { "es-CL", "66e39b282adf626f7350fc7cd14730737f26f916a0ab8d57fbe497e3f2db47ab90faf93458341376c1fee878cd8f2ea9bb67111fafb4774436961561e7e5b865" },
                { "es-ES", "393609ae29ebdadb9eef0c0304a6aba1731c13ced38331263db7d9551b6350ba3e8cd5dc91226903ca0a21e3fead19b1060c9fc836b9570da3e970e026882d98" },
                { "es-MX", "e48e52428d64f878dbe0c26632ac6f58b07f49654676149b144ed845ebb356f2ce712e1fba18270a2d814cd66e28dc66aaecf9953730f23756bc7ef0da4ed531" },
                { "et", "1fdba3b5568e7c341c1b2ce5421325f10def4b829ac65be4fb3d56b9fef807ca1437ccd573dab845b7a70579c65a1a38d7282c61a9f8ee3969a268f51f534c76" },
                { "eu", "d16f506deac6f5103d651e71b562e603f877c4487b6f72bc372cd773a4ab1887d76367bb405bb51573484240e060aacc57f55b19b1372ca793751bfc822d42f0" },
                { "fa", "f2ca6f9b7e17c4719c41db5342376d248c3a792fe5979af52d70126d231ae3785b6ade7a4fa8a0093100467dcb9388c5d4d848675906c1f2aa7061330b21c69b" },
                { "ff", "b76d68b965729b9da874bb9a04fd71985d36f019a7a552dcf6e9c3f2b973fcca4363057903d13c38a1ffbe176c171900ce4118bc51ead51a92c3bca3ac4a72c4" },
                { "fi", "f8aec5df2b3c903671d37a3c42685e304fd57ec50c32bb15918aedb35a2399ea4e2ea8d1491eb3bbe9205ec3ff140db274dfc924f65c3ddf01b39a35f55baa26" },
                { "fr", "78649df52465b18c2079944bff6d86daedda777f7d967bb433b5b80b72f4fc6e0c79028fa4946a9f0d590bed7c88d05ac6d06121d64c03e78800924c444ead9a" },
                { "fur", "59f778d9c86e1874e1e43faa30e5bfa8dc4dba99529b90e2f1a1f24013b100f44ed0b6cd89ca5b0a7e28dcc2e6ae9a3fb24140580fa3ec667547d0ae61390d38" },
                { "fy-NL", "fcc6ca62a96b40c3ec68cfdb5f7c94304e15be9f0b8570458c2a3f9c38a001a18898d678ff74b1456da5e033db46feff56d6655f229141fd49c22fc07d16bd2f" },
                { "ga-IE", "25825fa31930eb2d70a0a9e095ae5e445f648c45daceea0c3f6b62d022f9493703fd3de45f9298618ff532e92a419a27047866aef637b8b08bfedb3b1251bef7" },
                { "gd", "1bdbef946ca32570c593a6a76205eddf1cb0d80a30e9f7478614cd3b24a07e25726b71a937272f7b1af1020bf0bbfdd03c3d31e937515399872517511abc54e7" },
                { "gl", "d0d20bb8dcf53f5ceac1558275def06d1dcb4f6169accbd6f157a20c261b0b6da4d1498a3e9747c99d1cfbe46b1df89887476cbd6517c2f381429542ebe06018" },
                { "gn", "12aceaac8a465a6c7bce0b4df191894aaffde08fa1a91b81fb785118fa709ec6e88a3aecf191eb811507265b32be025c7f2cf3b00b3f39e0c4315c0851b16b1f" },
                { "gu-IN", "dda33f593b692a94543d2ef66a34d1d6bf664c5857847349b91313649587e49f3fd2cca1058a0a53ff2eb31d46221e2bf375cac15a341562583e78517483031c" },
                { "he", "993ab3932a06f618189854b5099a6e1a1c1553afab28b207a05f0fbce37bbcd7cca050c34f2fdbced812b90fa2863f0b7690c102e000e2366753881437d24d0e" },
                { "hi-IN", "b8dc7b4d69238fe8cf70a9187b05382f19ace0eb0538b09140dfb021cae7168404d1a0221aa8224e22a3f1d1ebc60b9bdef6940f2446ce685e03489049d78bd2" },
                { "hr", "6fb9375533bdbe2f3db2f06f18075a03821f21b43384259c5a28d870b23f29df307512c65b772d74b22f46b7a8995ab2848c95cb2d72952d6dc7f95bf77afaa4" },
                { "hsb", "6ca66f3a57b85b40846373e2658cc223fbe6967cd2ed5b4120c30dafd239e35b9d23074e66fb275bc2ea401e92905f6b086343015928c53310ebaba96501c03d" },
                { "hu", "f3a50a55d97d5e9443a7735e586467dc3708a267cdea41ac5b6e631537c5b2602c5e4ca9a50803a17b0cc8a2e98f310fa9ac72821d0e59ed8a729a75febfa1a5" },
                { "hy-AM", "7f1c6312fc45bc0d1fed4147b94ea4e6100c1d43dbe5addb66ff9e65d4450e60d5b716b4cb922e752ed7fb256543f7dbe9caf6f74408f03941c5c0e8c4f3165e" },
                { "ia", "5562199f6d810c7be220ff352d3bb443f6912c5724d490422a3caecbe101d9ecda564c9d8443900a6968fc8c4783f2c282ddc7560c14bac79b874282919e0814" },
                { "id", "66771271f1727947bc494366ffc865b7543db784cac0a5c3685fef2c2f5117dc9c7393f3b716b393c7de92f75af6b59c92441e395af62b20a2f63da03717e72e" },
                { "is", "1987247819adcb498b8cc10359eba35592bf041442ebadb4cdc384d61d241ad20e7cf00075b0008dd10a565497b7db3aa407f252d8bfd9f586d0cbc78f02dc20" },
                { "it", "9478b2580349bec8ba84fc337dce3ba494d2bf3868802e4f693785ad2e6c0dafc3a75891aec70b735631447e62146ef81a27c62fe15a9f9ea41f2652f987eb01" },
                { "ja", "4b293f72d27ccc17bf317ca37aafcb394a0e563090d32f75e8b9cec579c1b481095249fa8c402b008f0b5ec5bead29c0956c54eaa4bfa0a790c32bb956b956f3" },
                { "ka", "e6103af85a716da454d6f67b6d6d3516a0296be7246a74edc3809f38fbb4006924a11bc74f93ed1b798716d389e2ce63062a54ecc7b9115b9bed9074547806b6" },
                { "kab", "b8ed144f372752088aa73563bc72dcbd20d55d055817e6e37b4d6a07f115b927a953948d37789459dba09ad3134cfc7a466f2f54df156770c34d19e7f314f643" },
                { "kk", "ad3c929ca5ad511a78836a24b8ef158a2df730b9f3562c58c1b5198984c661f4f3c09fdeacb725b975249928f4f00165e5a0307d73226ef04c924862d3981344" },
                { "km", "9e1950b6793bfe5d82b32e408ee74690492dd33aac4a8d2bdaa50c58df35eac611867842e7140b04ad5d5c58f04a2b3d8173b7bfb87c12d91187363980bbe3a6" },
                { "kn", "2e0ec8719cd2af1803b82e565cd32b716385d9cdfd95d2e04ba6634f5749235b3e3c0a4cfcaaa32c933bf7b67b80adb74c6ae2b879247de91c0e08853588bd3f" },
                { "ko", "101bb198e7f8c7e3578977ae476b59c5149febb0f24c257c915e0290023e980314c7881500c5526d605844a28419796584506000d6e6c48c218cdfea5bd3e269" },
                { "lij", "c867c043de03f66870ce4a868b4ce2430d79a42b562225b57d1ccded63de3133a8d34289bae91173e49b763c5039f03059b3b7acb0cf1f35d2860643e7d5458a" },
                { "lt", "1f2b34c3bb3d25e3b33b6e4a71d08cd97a26ff1b0c89a0789ebc049b4e08d2f68610749bde6184e7b5bb184d2c893781a8c34474133566e47061687c182da1bc" },
                { "lv", "4ebbdf0ffb943674e6049496a385ac9b6301e240439b37254a9a38ac8fcb355b2b267391ec0b7600999001168a9efa1a3cb14c95dd827d51652f7e5d45c9c286" },
                { "mk", "ef911f6b4bf97dcfefaccdb12f35b9106780ae32270135f5f132d827f7a12df08529c9d6c9c4d29439f3ee0c083655e9fb07a08f291e1f030dd39ee9975d2246" },
                { "mr", "14ee59b336ba4ee862a757863ca34a9d39872de18be67238fe0230a61a3fd52bc3046a50cddd3da3e5c86ccf4e8b966026962ba92d43446d407ac0fff7615229" },
                { "ms", "c681b2673d49f8a360fb8916c267da94b622d388301da7295ce1f6752f2c9309748c62b7800280afa565a1619f1386192c84539122d42468fa1160d3ad862813" },
                { "my", "0980806b5f52a24a3fa7ecfd189c3f3ffda14caa4d2a8dda2c11c5b7accc1de8fc4e5f02269e1bb76740b3989f593e25eb994a61d365ef8c4b76852a902c45a9" },
                { "nb-NO", "10c5b54681706b9a09ade66b68288f827307c620ddb9f813612c64af119f7fcc0779c1113c9c5b6f2b496a51b4f34368fb2f198dae1ad5dd5998971b6eba1e9d" },
                { "ne-NP", "7ad1b911f116185614824f2c74922461a77217ce58acb8def339f33190b42ae0c381741760460a523a4acb6472e42b42837a24b27a3bfb1f14a81fa4fb2cdd46" },
                { "nl", "5866680f54e1e101c0c84dcd4785451bb49f2c6c84065dad7eb76c2e593f876cf31261892be902316077445b2a2acd03390d10e82ab8307e507dab3616e6fade" },
                { "nn-NO", "decbe26531f34f382fb7f7829691a4fbdfd36e76b18f7cbb9f203eb33be0e25083dcf704a0f2898002e1a3ea07883d626e1c5ab503d15a7778b2f006358376ca" },
                { "oc", "b20e1ab0b5215c7640313e267fd9fd3e5f7861e6a20817b27382a9c6829ebc83513329c4e54426ced1827c3b97e168979744566abcd428626b8ce63cc9a11920" },
                { "pa-IN", "a7f57621a7578d9863918f342df1b7d05baf8582fc09049a736e17ae4bce2260cba531490708ec3fe24572997edd0029240158e4955f7b063563de6702ef7cd7" },
                { "pl", "996675a15dde56e3c9af42b428a93ca60c4713eec6978ebd42835b847e19a123cc9ab9d94b8d27cb526c3efdb9f4bb51194aa7eb91771b6f6786690d112fd913" },
                { "pt-BR", "aaf26ecec2811ecb780c37e0035685162d9c902c7006cf6b65b7cb91deafa1bf5c36cb5af6f47756d1c58cdf75098eb4a634fd1312a12d7d3323ae8fef803370" },
                { "pt-PT", "a57bc25e8fb2cb70974abc9b61c94fc69e4b75b2a36b732a81d80ab7378072d27cfe84ec625037aedd1fac40748fb42a1f66c21f5f5464b72088ee0715f7eafa" },
                { "rm", "3899f73b8ce2ccdfb5f422dca650e370dc169d81d4b552be339554776b1341857a0ad0fbe739a34899b1a2ad249de9cd9b01548a317bcb2a8572d386fa93f98b" },
                { "ro", "38462f2b76bb007c1023509398cf7502c346134fcedfd21f9b4be692278b773cbd5167e763fe01c4e62a7a01575da31708cf842b59f8f92af421fd668e530288" },
                { "ru", "7f1374a6c0ea3dbea99cce41fb49d3a3c028c10a2ee3e203274716c86265a4421f1ae70b7657edf69d87d1ed658caf72e88c83a106d4dcf7afc6eb0871d87d3b" },
                { "sat", "5b885a535e0e8cd88b4e11db798392160c95acf623a13b5106a1432209721e25a74cff7b4b9e674a1619e884c7d20dbd3b92adae572bef413b254dd4e89ec669" },
                { "sc", "7ff8512d2fce95996b4f075c1ad588671d2a284fea8cc31890916cca28c45efc21f16ca862f2cf650ebcaaa0b0912ada91c48bdcb99bfe8295410a672a4ea22d" },
                { "sco", "67ac4e2a6428b5b73633fef8b82a0a43fc06e5653673d3b777e7210843a239684ab7daca40e2ea9954d0104a0031e920a6c0db99f8006239a97a84e4de010af9" },
                { "si", "40a54e47a2991c37a5c4c5510b80ff937be3a4a3ec1f015e446e44d2f4ae8ad8f8e6e7847825a3d55bec192a03df219b18c0ed2cfc7b19c869deee2ba6e830b8" },
                { "sk", "636401970fe682568c3bb523d28c0a7f21bbd1ef555f74a33ad2168bef4e6c053f0bbf8d30c06c71b00d385c630b503ab8f3506f2352213e8699dab8f67e00de" },
                { "skr", "042088059ca451e7b84ac1df4f0bb5e992db17d7096e6d378187bc8f3d25c66e00fd417fcf47d2234d1ace959721d4b41942e5d230cfc38c9874c3096bde9274" },
                { "sl", "4d9168c62ee41cf425a20ee0602dfe74bcb5a789358d7bbd5d56e334cf95bc1935cc2449b2b20c89cec24347ea36923f024dc727b339373603fb5120236f3dae" },
                { "son", "fb7d658fd459c4362a6b9b2d0800e087e44666e5892d7751822d51d7643062a15ab72e6ec4bf8356d9288f51df54855ec430001db4d6a187e3c7dd62c6e00fe3" },
                { "sq", "74d05bf6d91cf750e86912bdff14a2c3951a77a57b21007fb7b21742bdcc45a78fe2c23742172b87c757e12ad45401edf577ab0d71cb3e8fcd4b1fbcf45525e8" },
                { "sr", "07685f717a8413b4d65dc038f56582e98dc5d66c1bcd79a90ad233c2325cc298500f164e9c63f3e9c97f44a8b487538402189da87228a4528c4b7c0542806855" },
                { "sv-SE", "81f40ca4b62f7fcddf41f3b3df9ad13420604716ea69bbdfaceed0f0c9da0f48769faf04cc56ce0029ec8661b76380cf54057ce7ecb0be083e4ffdae42009503" },
                { "szl", "adc7e25619e0fda3100a02c35e832cd1ffb9260d1a1254c287c8930c762a6ae38aed537ef05d257ae86a5dd2391e3bccfd3e4bdcb99262ff34e1ab9a1e1dc258" },
                { "ta", "fa54b3d35fa26d54e9c8e0b98ddbf92fa6dec9a230705f0dea0b00c58b35154b7b672bc36313177080ed2e81ff287b158c5090c16703a94f2254b69b30a29125" },
                { "te", "3e9e1576fb621757a8ede6bd76a846a0877ee16c7fc3763885ad76ae265b5c6426d9ffa22acd24c9b1e7eca179c3cf43a6dad0cebbe43ca3b967ce835e1e3a02" },
                { "tg", "971305b13b62913493c691fc3aaca46ca62292aefca6ed02c3b8577fd83edafef0c93538c1407cfaecccb51554dc90d0dea1f977912df2e1851890249bee9c9b" },
                { "th", "5640c24e584331c5d911c2569e5010fc007c76bc1d3b0e341a5e0a3218148fd27918d95e1ca7768219d81df3fcb5251d1993d97326889c2f133afae841ba2583" },
                { "tl", "65d55d3346ae46bb044b1606f61bf1ecb1ba51ac11a1847f470ef2d146a049196ee83035c5e7f9d4cf525fbd5930422da08a6b296e95f7f58ab5c61fe19f9803" },
                { "tr", "79f266e55dc36d80635f4996c2b170a44395c5b914c6905da475123a70d6881fb6dc4f6fa6bc9ed7de7d00df972d78c6fd53131bf0c09b4a0b432da0f06bfb49" },
                { "trs", "6652db0a19caa9cc7644b0c3452060ddb56fb5a4ad6c03da9ba834afc48d385ea774be93356af4c4aa8915c4038511923b8d306e26afcfd31794f38afa9be8be" },
                { "uk", "0927ee426bdf4ebb623da30d2ee12d6cdd7aa2c7f85d37a6130f4c5c25883ea5fb15b1d405ca78d38ad368968fc4437e1c061a6d0902f7a85202ffc291e6c72f" },
                { "ur", "0f2cc18504848846801b3cd45f694a7dfb64d41768c36bb210a86bc4eaf58065d761be725c45a81b5f4f474e5194659c2335fb86e50056131555dc0376f196dc" },
                { "uz", "5fabcc9a55f948a86a4a8d21e123acbcb919c8cd8c75002d4041caac2f8a9fdc2576dca2bdd689fcb787214ffd6e3803a406d5f40beb3f588dd560b9f74a3f54" },
                { "vi", "44f1110cd606b49950750d8d8f1015f958916b55d345ca020f09dfde61bb0fca190a9875f1d665b3b24dd708d805adfe4c6a3bd5292345ed58c4739489e12518" },
                { "xh", "c2fb4e3fed6241e6ca6acf01eb4c142a87ea9d6678871723f7215fb04bf405a88c30da549792abe520f7cda3d1e224b187a9891a3c629665f0bf60ec36c7a9e0" },
                { "zh-CN", "fcc0729c4672f64e6ec87205422eb8236a23c66c5f0b755757b23bb5e85568586e8782b22a18153cde5693f347aa325d125c9f2d9301e79a354520adf85a35f4" },
                { "zh-TW", "ce58958554e9abc0e3c1759de826d3c648e052c59892022b103002090500242fe4e2859d57d2761fbf35c2c5a6db22bcc7efc7bcd1e1332087f98002c1256c60" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums32Bit();
            return d.Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            const string knownVersion = "156.0.1";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma")
                    );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["firefox", "firefox-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
            var handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false
            };
            var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            try
            {
                var task = client.SendAsync(new HttpRequestMessage(HttpMethod.Head, url));
                task.Wait();
                var response = task.Result;
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers.Location?.ToString();
                response = null;
                client = null;
                var reVersion = new Regex("[0-9]{2,3}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "/SHA512SUMS";
            string sha512SumsContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                sha512SumsContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
        }


        /// <summary>
        /// Determines whether the method searchForNewer() is implemented.
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return true;
        }


        /// <summary>
        /// Looks for newer versions of the software than the currently known version.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Info("Searching for newer version of Firefox...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            if (newerVersion == currentInfo.newestVersion)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if ((null == newerChecksums) || (newerChecksums.Length != 2)
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                // failure occurred
                return null;
            // replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksums[0];
            currentInfo.install64Bit.downloadUrl = currentInfo.install64Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install64Bit.checksum = newerChecksums[1];
            return currentInfo;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return [];
        }


        /// <summary>
        /// language code for the Firefox ESR version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
