﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2025  Dirk Stolle

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
using System.Linq;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Firefox Developer Edition (i.e. aurora channel)
    /// </summary>
    public class FirefoxAurora : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxAurora class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox Aurora
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "141.0b5";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxAurora(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = knownChecksums32Bit()[langCode];
            checksum64Bit = knownChecksums64Bit()[langCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/141.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "84c768926bc09d910e795b4ad05b2bf8f47d65de37e795a061b1a52b9c38b273de3cb38c1c60fb854ba53ec9494f934221b73a0663943551a7561d32fd65365d" },
                { "af", "7b9207057f04184def51b6b49dbeac2c014df6942dc49f9b4178fac0ec87a08c2abeb3f1ed7bd158422cbd8794d9c83d4f76edf58068d4d10e88b8e4f0a0e236" },
                { "an", "a7715b97e0b5af2d8b8ebef0ad45a9feecd785650e6c11090ac4d81b4998275926f1bbe18c59be39e71ff661f0ecb978cc755db6c110d3858fb3a64a68194dbc" },
                { "ar", "12f0260671c2fa65a4635755c12e58b51738ed4cd0c459b4ce0b01f3599a9b9d132fdd934176a0d41b4de3f672424911ded07d362f349f86e1374478da833809" },
                { "ast", "494af956bad0563d28a8dbc6e9a85d5fa8faab1864a2ba2fd9329357c3ad295d27f0fa8c48affb29e95844f5538633e4dfa50612980c06bebe81aaa8bd5d8d26" },
                { "az", "47893cb6886c8baec864dafc165c98d75036de43111459d973a854654ce2845b71b5ee2c74027684da5c00d5a602c19f2ab45d90e9cdc8328aa43a792d514d5c" },
                { "be", "849af88eed6b092c4c3199f22e92b86ae11d4389c4a04a19a878fcd8247309180c051878d86a2e67604077df5720c931a404711aec93cf7bf2754443d6a2d620" },
                { "bg", "b3cb2917f804cfd1e3478975e8b5ff3fe26bac8d5ff9e4fe0217128de8ff1a09a344045c201b5ad243607fd07b5c711e1f7680776fd1cf8bd704f46ab5b6d99f" },
                { "bn", "f9a9a24ad17d4e5488bd9b70c62429eec5e5c9aac6166eec44efbd76a145d084ed00121f4edfef4170095b2efe27bef3868fc4d3da82e3a7a2936558353eaef4" },
                { "br", "b743247cb10c7bcdb396ef33c073511a6af45304e39b92c030b1755f988bc912e32847844a9921a873902808c3f6b8258345fe7684003c49c5f0ff791039ae43" },
                { "bs", "ce4124c856052488b33a8654ee1c79da98a6ed16546c5b20c78dcfe5840058a5674f7953d007efa9ac909ccce82a17f68c6909fbb4af3b7142fed72730953e09" },
                { "ca", "0aba4ae88dbe6984335c667ea0a6c9930b47187e545730383d1ae51e67560b27380703f7ac4b3e0f36ef269206768c41338c8bfdd79f7c70dd037c432a6e8284" },
                { "cak", "5435e6c76e6808d2428c965e33cffa75c0875f5f2dad37b84b042ad927f5407c47492b621355c55558458708d5e90881d0dc3ed7bb53d84bbd3e5fa8e4b8ff53" },
                { "cs", "4cec338c22bf41a79f8aea4c8896c6f4d52b288fe44992b0459d1edcacfbc13b4c34a813abf47b9393251c8f14c8bec736dd95a222ccc852c5bcc896e4f9d5a8" },
                { "cy", "516d33413ca76b6a35ae6ff5f00a893e67d3e570390d98a139f3547410fd34a23ff6ca962a21ea4e02074174007b1de5f99fefe047cd7a7e621d09c9c84b808e" },
                { "da", "813f1be1f814a54b6a19b1a6b84a0225dcba9c42d58b4c694095de12e1b6125bdd5f5cd1169cdb652be41cf5fd1093c6d646f2db4c5cdfb0c5054866a862091a" },
                { "de", "cf7a5f508f2aebdf4387613a6a6382912010dcfbc6e0731ba365403770f087501abd0baa4af94a834e3eac7b44952486c9439a2a8999bf69c93af0d5c71388f5" },
                { "dsb", "08c428273580d47307b9ab64a3a4f6b88fdc1c2b3e8389d0c32724c87623b831380f91529d5421b361a589ef71a4d1116f4a942fd96db5f9287bf303d58d37f8" },
                { "el", "629906258a2b6157d4c6af0b643bc96c2b5a2878d6cbe44d7a44c7ccdbe0d962a5f90b93ea688821b822115f3783d7f1244cde4d738c282c8d771967dfaedcae" },
                { "en-CA", "13b52f299f16e3264584ba829fc6bb42796f3d93d4158ffe01b497a7060cd7733e76ae74e1ccd75689947f1141fefbbf339799838b990231c18de5b9f6ef34a3" },
                { "en-GB", "6d1c47a54e4e48981466678c1b67a8027332a1a74bf0aa6c89b46d74f7ef769e47c886131e1f3f197fd41a3c21b0254594123bd10831a90de471bf4bce3cdb2e" },
                { "en-US", "15ea7ad0a05832bbc08d034e93e70da7a1af63933d9ed5c5efd7c74ef3f8b6ab67c9434226d7502f5c1bcd80abfbd66ac640bbc84c5359ad885973aed739bf80" },
                { "eo", "fe5c4d0cbf3b6e688af1ed0bb2f07be87212fff5446c91049e3f25ecbe32bc3c067bce024abf9dbac4a750f08b76d5f0307d935300122e9378f878f92ce78b99" },
                { "es-AR", "e3b3ed4fa696f2792d7ec3a092b51e01a57fc3ea84a64035218a9f445ed1a62e10f3b6fde56805464da3005afef125c2e8f9547a517e5ad0f0ad8286311f6361" },
                { "es-CL", "3b88bf6ef58cdbb0de3849d727df6470524b6cf5c1a2c05f51c1f5966e644ce13722eb3d929284bfdc3a86184c70a2d47158cb0ca3964ad8e9e000e0f217ee7e" },
                { "es-ES", "502d944abd42cfd615187ca58d18df4ec05239a0f828f8211d065a2ad299d343edee4cc1956c7831d762c1d2d2d3b1e83a9532bbbcd7c21ad259cf144efcf4d1" },
                { "es-MX", "715ac94e4b50c4aa70d2e9d6f1c3c13a3c51e5996c08820fd06b5f907459045373241988bdab5b26c3da45483b33bb5d09f4171ca79e1dac9f049ebff24507ea" },
                { "et", "97ebe8813625e208f52da7915af3129e70bacb88a4066042cdeab182453ac9fa40161d9e1dd2b409b7ccfa81c90075d55d3ec688d1a02e688dd8f3db52a5f10c" },
                { "eu", "6bc78c9501d8a2555a7adf24867c9b83116a737e3a86f9d07a8df5c46a3df10d1d45f2bd00f5125d96d6058680a5689e769b03a2410f7becfffeaa7daf883e1e" },
                { "fa", "4a9fbd1b1a06257df68a399423051b7a07107f97b5b0df198c2398ce81794708306f64def5955537778560956c9bd4e608aaf05ceec4c11e69ac0f8c204aadf3" },
                { "ff", "822f4e31746e69f89e506d6e1b5f8d91918f80fc7f6fc9f1acde446cd390bedafb973a48fbb5406c6f7866f662625f34d146a9f0d7758b996790d858195c94ad" },
                { "fi", "134d6fbe5f62af2ac364fa4f35f02cfcf408fbe42a107993fdf3da6480cd1c0815f3f960f0c30f6865b6e6d595ab4968affdf217eeea3e0f220cd8f0741668ab" },
                { "fr", "a2f148401ca3682571a6613963879d1b9a9fbc129decae9a4ba962c0adb28796279a9060390a2c6b1957a7404e2adc0c28260c429bdd0224b35bce27a516dc44" },
                { "fur", "58c8b75068745107b640717639691bbc4f951063217a7973b40cbb907aecc073042b5563e9e26c36da74771a2863c865d8f4dd9a1e1d430824c5f69bdd35e786" },
                { "fy-NL", "09d71ae22d68656044664f0824e150e8df6b53cdb1b12a6f1ef4d9b2e1436c993708fabdf8b656e40e0636fe1c2eb89be83ddc0f58d608633545da2564bfad63" },
                { "ga-IE", "01e017085f8156d379908a00abb32c3025dc5e378d4ac63cf8ab92b23243ac6857b1b8aef11a186252bda93b0c8d6932327ddcb2e53d144a564c44931b947051" },
                { "gd", "a62cda49b2a74a50b94885db5ad27880498d6661e8afa49014fcf088e3b43802f096533e185e38a2b78cff732c6e6c51e59e9095f5d73d2075cd07e0b6629e48" },
                { "gl", "8d5e80f9b8c3e567f9b75b782285b3cced8a4b693f0d7c8aaf74220aa92a001d33271c3255fcebbffd88872dda83191ec534a9f13784be18ebfa587d970b60c8" },
                { "gn", "7af8720b848fb894daba001053fa97c4084f21d10d1a8f252f5d03f7af00a00bdac4b3ad09b113bba7c85a96c95e875ca40235ae273c871f2b0cc026233fa264" },
                { "gu-IN", "f7b4878ded23e478b50774d9ad243725fc35b4655018e7f12e6fb9a5789316bdf770c75d34342d2bc5c06a31c4d0a25b5f0a121c2db788d36c1def64a3177ac0" },
                { "he", "2131d63967a73220bcfc564450f9d186ec90200d45fefc0f73f8b8b3ae2c0c4c0cc8b05bb40d91ce81e2f4fdb9435c4196be947f622da35de46e5346de3b9c88" },
                { "hi-IN", "39207b1a4d67b8236290c250ffffa1586f77f737b48d50783e43e9578176c08b99cc30cc9f1a3729a0291dfc1137370df6da4a317bb128992d2eca219a3634bc" },
                { "hr", "c9c120cf16f152d0596061569738fecdaa9608fa7d38840e159ffc976006804671ed2deabcf8a0b6a5a60ba6c4fdd8d3aa4c0f9fbe02b5400dcdcfea65864ae8" },
                { "hsb", "0beec5a5cec588288c4fdd497b165a51210efc352d9d698efc455fbed95896de00996f06b581a0815b5bb97b0524f2f554aaeeb225e29d8da397626985f09c28" },
                { "hu", "84c6befe7317b9677fa5e36a25dbbcc14721424cb6bf21f78a665c81355bc3792c3df7fe221777a16c8d01789e4094db3e175bc6d12fc29efc3b38e9e8ea5d48" },
                { "hy-AM", "ccebec55bf17894658f8c3f3959ac0c67a2cc94607588f248e5cc4ad4cc8b82304dd623fd05d03e2b80d00b0f6f0d59b943e843b47d360bd19d4d4e0f9d8800f" },
                { "ia", "a63b49c45218affd66ca303a28824e28217c5d1da3be326b67633abac5bf3d990be9eb34aa30992de67691b8fa315a9ab656cafa6954be5ce6205b08564fa6ed" },
                { "id", "3dbca6081a9cdbae3456b346b6694230dcafc9600ce1f65af7e0837665d6ec701f2e5d7b6693f751fdf2913647b6374c42d3877d651ed4be3fe4fcd3e6bbc814" },
                { "is", "400c74b83e6e1fbcc9407ad045d930f55e459b65cbd1385a5c84a762f885597ad2e6e1ec9a995361e11ae99b7d556fef67d7653e60e62ed3384f998e72435ac8" },
                { "it", "79a7d87f43e690d4f52911e102b727756b853e3c4a7ba06931c467d2ca93e3b408629da4cb512c164dd803bd1b04b9a51512dea41c103ad720336e723e992bb5" },
                { "ja", "4c492f414787ec904c948ee2d605938987412d5547c27874e5085d994916242ad2b000e52bd9783b6dfa20ca1fc5a1ae2f780774ee010a21f5e5c8f9c1863a39" },
                { "ka", "52e6668936675302175c7062e2607c8b73e707192413e3965ff031f7987773a002536650e42440d99b9c8930cec627ecc531a43f98fee29c95caf334884f4460" },
                { "kab", "7c609175641b051934e7470c6aed241281324906202975bca5462da974b4f393422563a216ed1744b2bb5a2d79cf8e367b471c090c539c0b36c68b941de10f1d" },
                { "kk", "1a1d285c3474da0d83855a432a6af2f5ea8070c5e1b572db98287ddcd9fde3fcacd123b46bfb94f14f911b2d2957f4b764f3baca950a58464114c88605e449c6" },
                { "km", "0814c89c74bce6c333b7db4b6dcd77e27e5867e8f31a04fcf030c97f9ca45d19aa05d4b8488923e756d6f0fa11d2b8247641d84211762d5076632cdc5c8cc901" },
                { "kn", "6f81a3911f18b06b0494d930631c48b676438176c584f591838f80eddf61a8cc2f0b3d6b2346f39637ca58bea301504b082527e03d7e6917df4f575c85e8f9d0" },
                { "ko", "3c4defd5de668b997fcf1d95311e079234f2b796d27c754d04337485f44d4c9f67b58de1027d066c7d81fefd07a5c85ab97d275090bb0fcde590a250bb475760" },
                { "lij", "d5b6ec056c4269df959427c56d78b17a9fed2034cf76062e37fd7506a28d1901daf624f7fe5f707afd33b443fcff02db147df8a9f44667e0dcf0a40e9a2f998e" },
                { "lt", "429ac527d3111e81a8dd9f122daf5f1f6bd0efbdbe3762217fc8ed228890230085f89b5248cad4403c318c0222adc7aa6020526fcc0bee6e202ee79d40bf2cbd" },
                { "lv", "61d348f08ab8473171aae04a1add9913f349d15dce67fc57e2e4d0fc14a6af93b9a43865479412ea9432ab9bb96fba2b33844db35704beb5820d885c92b02b11" },
                { "mk", "b711b0a83db293c52dd5045e126598b545f6a8e2c79f0adfc3c0709f5c87190b337e67df9f688c82b26d46916c4d63dc92939e5639b78437097eec95e4339063" },
                { "mr", "acd7f54eb3bd357a6519566d3cb61d71b1b9fceb3aeb4db33d9261e35ea818ae228f40ed23063c25effce38c953f6439dc22a3f80a037058a5f24bba0114f2e3" },
                { "ms", "c2a598120158a9627141d7fbdbf19de1f7f96d3a8c2a8c7b2ec1cd18d2dbb9048ca71089f7bd6e2101b92a9650916418120dc4ae622b0b03a2307443640d9f39" },
                { "my", "259472da74b5db49ed8e081f700a8fadbd7aee2b1f645e4acf203c6d1c293e35665aa994051adf18594960b74d823b618aa35af94ac284cbb0354b4daca1b7f2" },
                { "nb-NO", "4d6f3fb91c5c408f24bac61af7fbf8a526d1995e7ab715cebe6b1dabba1683c7f9da257c3c193b6488e299731d4302f27f06fe0a980e51535dd8551b14e8d3be" },
                { "ne-NP", "efccd6575bacba1eecd097fe7badb74a16061e958745999eed0be47667bfb4d0f2564eff81a4a2e8be93b54098a29c0a2e6773c8fa1a20983b3b4c40ec3eb4e0" },
                { "nl", "6bbf7848c98600975f04a9f475e32cd8f956753e332766f3a5828595b03209f61fcf01417ab491b12595629f2ce2072a4030d395d7f276cb621307b25ecea54d" },
                { "nn-NO", "5665fc1f828ff7400eb07e73c91c44858aeb35cfb68101b1e14150e09f86d26c25f9d147271ee77118e79f9a3b4edbc28bc70c50730ad0e026089feb3da136af" },
                { "oc", "0b70fd29eb187cf6149afdf899d78380bd6cd7a9738d17a5adc6efeb34f32b99ae5a940f4a0aa9d45a0faa11d331a5e2d7a6025291f5265f713a9f0e6b77ede7" },
                { "pa-IN", "7a100980e3d68265b017c6a04133b387c120a5ea7c2a6bdc7c6057c02f122bb66dbe1c273de56c2b9e31a2fc9c094292aefd77b5908ecd5dc55a17cb57aa12eb" },
                { "pl", "f4a240a0a429589a4b98005966295d1a80ab245de1edbea9c1419a8e427aee70186488d71cf71483fc13e7c5ba5cf7befb0cbb9b8aa6e69d14f990f4477ae2ea" },
                { "pt-BR", "c68e3f8d06ec728bcdb5d9b7d4bfd505225e1efdb291ace94d99f709788e20e493403da919c86e12dff7c5f583af79262f3831d0e49c083e6e9f58e89dbc2446" },
                { "pt-PT", "c5b7f951a2804b7f287b402b40e0a3284ff29618233b4a1b1d6084f944176433a386bc3b1f93eda3f64d8c409833b55f90b20a038628a2d7d5946474379fc612" },
                { "rm", "530934e5f09deae51aaf0005bf82b867ede2175d2589af74a869c4b21410f999a2cd1801fff8c5ba5d19908624dae7ea47c4a3553a60504c0b1a607d10e35424" },
                { "ro", "993b0bf9bf05ad2b2f48e71c3c7a1813b9120ccefeb5f3cc63eeda27d6554a8a6889f6116b5ce1c0948297dc70d2e546c156075f9688cec1a96e5aa94d10bb8f" },
                { "ru", "6fcd78c1ffe311e16fa789e6ac1ac49e20d99bdc58b3b061c3f158c70ac862d7194c086a8208cb5a607c4ca322b96f71f23dad5de0720136559c44a1c87c7532" },
                { "sat", "3a24fe652bd8b4bd32c0f605541a892d5805bc421e69bb8bc4e9be04c099e9034bd430ae53d4ff299c77f796193a6d6b676606c1ec3a785ad9fb6a2582c0eb27" },
                { "sc", "5c4715cd4d3df364573b2c0d38b8b3d07b7393a03757442bdea18468134247413c2b9efb20ca11f66cba1e274f36798f1edb053da9590bc3dbcbaae803103ccf" },
                { "sco", "1d2bbd3ed013c5d4e0efe09c6adf56cf616f758fe6c1fe78a158a12b2f9d5fe29bbc7bbc5271c1128a4c91dd9d4e5bfe574293a481e0dde699e8f5891a7b9ddd" },
                { "si", "30cbefc122b54693836617c1990239318acbd7ece441562d031eb1af90dc9b6feaab73cf48b3b8c2b7d2c9351380b42b444f4bf59c2d97e3820f14e080b98dc4" },
                { "sk", "13e3b9324fda9e1e41fe1b742cd90b46e40d205b5aa8235f61a9bccc3e501e1fc7be06f261dc6552c11ab385258608780cb3b0f7f22918f4f81e89897f222707" },
                { "skr", "5f2d5440fd81bd15d2a928dfaf27802f51a6e91123e7c6e1a0ea34bbcc7f55d77f00cc5941931f164a668822f352d2e3da9a6ffddf9f51ee0fecb26e7a9be082" },
                { "sl", "21fb7314a37b2ee12d21dd656625758b88d3b4071bd4bf2581ed945192fa062f1f810ef7ef956e5ea7049b4cd79cdfaaecdcd189e67cef6f6e2ede5a72d9691d" },
                { "son", "f651e0f12f109f4612a66fdb4e7f2055efa51aa24184d1b5ce7b561fdbe3ce625d79c7465f58ae052cc389396f3e24526ab17850590d1921e2e3c0404a5e34cf" },
                { "sq", "c8058040f3e843861f5523ce00bfe53d31d2604ed1e53457c83d85e79d484639c851b612affe623331303f13b3dc1359275bcc9c7489fde279720c1c79495622" },
                { "sr", "6671f825d6b1c397c6d7e727eff403ff73febb22532ec9f2b8cf80e8d06e102d63032bff9b9bd16c74a5ac42623e3a95fd1f23a371b09db3b9729aefa5ec35fe" },
                { "sv-SE", "dad3e1f79bb96f204337fe2c30d2d090e84f52ec945ad2a5b9c9609349969bbc6a293ac949c031af279c59f314834ada86e5088ba8bf776f99828fe3bd69fd1a" },
                { "szl", "2bc34b9612d7d50345b8142f2f02bd4b935a55edfd0aae6f0793bcaf64806bf6a6b0f600530a4751b702442573320c230ebeac5a1ff7ed2ad5cca99fef459e1f" },
                { "ta", "75c5d5ddb73f55b5e9690c3abee377abc4fc6518dc8a2c1bcd9361bd200c3b6b394af3354b9919455f8e4888b3b5d05f786a25d714a6cda9d45f0b8481d497fa" },
                { "te", "e285fc4c30c2ec5963b2c62013ac17446c6d79b39edc605c4c273ee1abd994b31a5e4878d51c282443fd66de2f488d88a22269410290a40067bc9ac248fd48b1" },
                { "tg", "5a719fe201e6cdd5cb84ca49ff9d61be1774f2675c4255d503e0f7b76ee93df3d3f66932b171c289b3c8702fc002a579f6b65e963ca60de62b9f43c425406002" },
                { "th", "17f5fba00177a72f9675dd9278a8c683dc716a582f0c88a3e22d6625135ff5a3990898ef4de3e08d2bc4fef360f483a131bb21c84cfae46bc9d7cc2acf921d76" },
                { "tl", "a1c63b3f8edd677f51a3d54d6b38500ebc304144782432fb518cb5778aa1cb3b773ee5dcce9d10b6a58eb96c5c805c85f3669b9984130abfe1aa5818bf61dbfb" },
                { "tr", "a207833ffdacbd9397e4ae88cfd2c82516897170e26ea1e61ab8e5c51e14620dd208cbccabab11859d94d9ca3079c27eca64a52a690b9bbb19a5ae5d847a01f5" },
                { "trs", "2a27bb0bc48a99ade04b56ae5d42bbe9d7711655d0edab5a10d6a95854f4390980baf1786e548f1faf52e0d91e6352f7e9061ce14c28e42c0c37722e130b1b33" },
                { "uk", "ff714b50a843f348c4f82188fe154245e060f90e60484a149b5a0348947b53f595ba5818df3deeab56cabccd47377683bc38a22769cdfba27ef53e84aa6daf42" },
                { "ur", "e63842402e55a452c0d635444ab31ab2b1312a25a56b16c39760f8b759e7b59868d77f225930ecf32f502cd7999e49ccb9ffaa305e3547dccdc85eee43d14f24" },
                { "uz", "ec301e017c105a4cceba09cf0575a7da3a8657d7da9d2e97e79a20e3b9a600af20151e7de6e7a333132b489a8d4a2b23120a79c1d13d95398d4accb21a5071ac" },
                { "vi", "45e9e78c495786e3ba01f49c10163aef8eadbfb5da64c7ee7ab003093c93f8d7e395089037a5b49bb300d16e2a8642e107cd4c64f8132e71f576b44d6af2c700" },
                { "xh", "8b47867980ed153c0d6f1d7a411c59c14b5f722e867f14c6ca1ee7b6168450e1fca1dda3ebb0b46ff2488fe6b2f856d16d5b7426dc05fe604d85eca2c1d2c949" },
                { "zh-CN", "5a79f98e2ab2e5393c9a5716825a0f313a83069d5f1b7641cd59ae44ff92d1efce621e9dc5baeb2e2e9f53c602acd9ac321cf253f920c4b222e31169d86ecdb2" },
                { "zh-TW", "accc6a69383dcede6b59b6995eda07ea84a06a0e0e896b2b32277f7fab912b2cf5b7c4c46db5f81be6330a834b01ac9e176d7feb18e9f503edc00688d87a9416" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/141.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "91011ea17c028e504de4305f4c7829691d927f3b8f91b090a1636d3bfcb227f9ab1824e6942421b308bb83edc2fbe12c4c32ea4413ac02a6fb874f7798696bd8" },
                { "af", "0b32511fcaea8d79b757a2a7eb06559a32254cf630279f44e279d7a6ac564663f5601e67e035b0acba082f5b80364f69c0423567d3439259844369dfe71686d2" },
                { "an", "c673d1582db546964d7443a0359117dea9ffeb6ad65f0f7bdf04e02f87cd38c44fa1300a0b67dfe91293aebde65e7a8c96f9d26d4e4b7106c6b2b52170351d84" },
                { "ar", "1925aba4d06af436629b01353325fc8b6ac847d0f0fc9882ce40e90bd240a96291fe1711530dc87abed7eebbb7f9a73e3c3982b4170ae1d319a0d0211e61d9b9" },
                { "ast", "5ae87dc127ba9787a490239b68fd11edf01d3f12d53762bc8d836366f9b2186ca42022dd7209ba718832433936c5873a087aa489044830a4c7663efae4fdc687" },
                { "az", "9fa0b733598cafbc54f95e144ec16fce7566c44786746bd9c91fa28df2ec6b6acaa673f5b2e7dea4a943ebde85e14963a9de32be3a52a0e79ce6f987b5146fb7" },
                { "be", "0915a8e23921ece2a381c528998c70114631307b012e59a9fb237865fb20f89ee3403c76d4d91592a65200e6d2e55e7bbd36c67bbb479eb9ba3adda25bcf457c" },
                { "bg", "6ddb36a67af9025cab09071fdc498b0cc1293ae0ca282b4b2823ac93e4f16c4ad6049185d8c15d30a2152b0974f8fa67066c9bbbc0d4ffbef6b14bdb3c72b8e0" },
                { "bn", "6a18cebaac3350adffb302c4e6a02ecacb178ef65a31d2c58801eda996177eac35cdccdc56fe66fff530eec2f2f6b49608617db13bc2e7cb15b60331f8b75a34" },
                { "br", "d0ee18bf95b87c85929333be2e4cacfd772e0d2eb7d5309248737c008f55323b68c7a2919a5546590bfea0ab33f5d30896c243f562bae1de98e732f342e3badf" },
                { "bs", "4521fc52e5e93042cfd042b7f6d066a4ad72aa012179ed822fb1d52c6af87299b2a50dff5c77c9c7aa4cbbcd2d15d6f3b2edb67aa29a691eef4beda121fed5f5" },
                { "ca", "a66e3f2bd3e342e7bbf533f48bf654abbeebe8ba13ef9f52c219707e182be025ac9052cf2abbb55f09582b25ece6a73e6f9552aecaedf99151c35ac21d38e122" },
                { "cak", "e3f7030e8398245607c457b67719a080c473e4708a95fc943636b0b370e072e24903ea1c3dc513f172bbefaee1d1dcad3bf5b402c2445153ab51f07fd5e9b5e4" },
                { "cs", "d389ececc87ea266200461098219548d06ca05f264d1fa6bd744363dc4f93b4df92fddac7fca5a9c876ee818952c2b744efecfac15bd7284c03ae77a4bcdeac0" },
                { "cy", "712fbd07818978f4716e5001084319975a72e66f3189092902b4d146f9731f7a5944c91e14737e2c7d49a3fd18ca944d17737feeeb29a84661be97ff3c1d9218" },
                { "da", "2f70379ec4e0cdfc7c6e3cbad5d596e201018d77b66057c649d9551803d947009d8e0bb4c04a7ef81fbc0e34d398d586c2b3604ca9b818ed150adbd974d5d653" },
                { "de", "c1fd78803a4d74677af1818696c9a98b2db7df36e5502f62506349a41afb7e8c5a1a8d1540c2eb75491135f5b309cc510e3b6ba9b2650ccec265faee85ae97b5" },
                { "dsb", "63ede2133f7994237561611d1cdd9845dff961383655aa97f0137b3f9befe3e83f3780ca9ff768b50c148a355dfc43960f84f5fe77cc04835ce315f715116408" },
                { "el", "35e3e832fe16729f8ad6222bab7b118692d0febca0aaced866e04a050e77e5f646b2a9fb6167ba3af82f9b13d81ec59cce1575a0b22a3bf49cc6ab8e06e04ab2" },
                { "en-CA", "ca8c849a894b4ff4aadb9264b5a8ad9e34f7db3f804af3e0421b8ebabcaf1972b4533652ce00008b321fc01ff6fbe0fbebfc124f30bd2b2119b377d0513b063c" },
                { "en-GB", "7d8b520c0e75ff153e315b9886bad7b3c1adf5a8cffe9e78f3fb29ce566bd4f4c4280817695d19fdeaa2eaad177a919c9ef442e6add0a039c6160b75677b1c52" },
                { "en-US", "8d1ab04eaec7521c5b5e7f3fb3f4abfdbadd9b814c1dad445be7c4c3eca290efb1778d680f3c9abb2fad8cc09ddbf77c6127b63d4dc9da9bbca2e078b0dbf004" },
                { "eo", "aaf12d41fc8f08fc681a24a9786d32402de06a01065b243f06c820056bb9a1656e86a05e188e9a22a503a1bcd33a9b306a9faa6b85b01c71a1c62a08c5ae19ed" },
                { "es-AR", "93e354563e724d1dbdf43472c55107e3fe2d18cb78097ead8c6f25caab68b04c1827379af35715109f7d48fb83295c18f66a0c19da6a71ba22ece3fa001a7e66" },
                { "es-CL", "5d76d7cc576def91c2138d6830f175a524e742c65117274b3ed5e0a60e878f8078bc17ff1ec079a252a05daa4029849e5ac6ce490228695e23261c6636d1b7ea" },
                { "es-ES", "de8c11c538418b057adcc4dace80ba85221550398f6bba1d592b0f74834ab0de603c6d395752d9dfe6d0d33dcc152ab6a6588df198ea8f2a0c6d87b4e1450741" },
                { "es-MX", "d540a8e59768ff5b5bff8ff5cb21bef034fa6dbf859e6d29100a1eb32d78420af40e4208f98562b73a532620fe3f576558c115f3b022569df319054c1f5ca341" },
                { "et", "41e913fed43d1aae6958c92a06de15079585d945ef2478e71844ed535ece294c5a492b3214180b879cf961fd9cc1d2acb2a64f6e70db2c60cb9e6c9c1d262317" },
                { "eu", "2bdb1fa30a1c429302407a658fc592a69935a43161a7c54bd741946633eebb81ed827aa3a27c462688e41abf9b9ba46d4708b8ba752b19163abb7ce5a3041431" },
                { "fa", "b7aa29a7c82b9ef643a76d5a9c1824d41969f9381cb01cf219747b9bfe9e5c5daadffa5da9a2d15ce079a803b1d0de6f597ddbe1582c0728c500895a3793bd60" },
                { "ff", "e060e4260783aca5ef5b7c43b4e2a55670f93756ed2e27975bbd12eff5b415894395f3fcad6debd39bf31f569f21438a02715d96a80d003502f83f6b5aed290f" },
                { "fi", "7fdeaf7f130b871e64919024a0052c48ff533f5fa875cc04117341d34f644ecf4ad11dda0d5839b1262c16afaabc4084c019b9ce2f93a3542498ca7df0484d13" },
                { "fr", "6f4431f581cd47e790bcecabce3c68f47a38a156e81fccac7db82379ccd672609b76785d9fca3a613ba0c3df8d38649ea19543e8c6345acbc2ad68cd2d7f485a" },
                { "fur", "4c359549459d966d43910daaf21bdaa90a7bb4fc7f976e16058c2c6d697f5340c3128ac09d6d81e91e383dd598a2c8be6554cdee79206db4247e823c10f8af3a" },
                { "fy-NL", "87279f92d8103d5ee58eb0a4413e07384838642a0093bfc4183ac7f2a43a1bed013b6550b6c38471959729defdb1f67d45b5dd90269ef234e9b133a6c5cbb406" },
                { "ga-IE", "42d3b5fccad8e435d6f33c9f289af0851ca80414d0e98f68c5482334f758b6eaeb104295a8ca980fdd5282b1517caf98e7c14c41c0a99e5db47fa2cab360be5f" },
                { "gd", "e45b11adf8362d27b465666363b0c3247321aad0f7868db060f4651e81ee1fadf4c4cfffcebb1f6c7a0441e878f4c9bf9fd37e636a734a29627931cb1e2675e7" },
                { "gl", "5168c7dfcc88f3877decb23112848b85f554b476375c7dad1bfebd4c2d75de415ddab2b3b68169d645d00beb665fb6a79f3b55b8341d5adc6e9be3f6ed9f5b3f" },
                { "gn", "2af5d371f73acd58e50b2c2ca549fa25376d738cdae2aef5b58e9cedd83f7b71c5646a4b8d3814075c0e5e829d7a4de6fb137efa9ec2c0488a2c6f7d1a0b9107" },
                { "gu-IN", "557e090c00102fa75fb716e9e15965c5d99352232941142f53b821f97e1b8ac39aa7027cfd5981150510dbd2dd63fbff4c80d7df7b11813e9ac086f491191695" },
                { "he", "d4c796d540344a908bc372c240dc399b46a576f71f6ee6c4aba43e0d9c3e5e44e664d5fb6eabfedabce2b7483162b9cfbfd9b7017e03e1f6c734aa0251bbdb5c" },
                { "hi-IN", "0ad23b86c9ebb2eae115eaa129cd9ad78ff9cf29c3f3db3cfd1902c40d4eec8fb94e168b00f290ee7ddc06f5c87e6c281bf20b741c0153093f9270844d03bb1c" },
                { "hr", "52903d657fdc3819ce5e1f6448d041d2b6cc30df84995924a896bffe8e035c0d4eb3867c66d12186f8df36497f5e6858741519dfe4a19a7cabab0dde67044271" },
                { "hsb", "6b506a460be9a5a4ee532edb40d62a0ea6020c7a61e68700809b40cca9c7fc58f1ff7ec3a5e7bd88f1e0995b57d6e75abd7c9872add7a2734580f1a3c51cad70" },
                { "hu", "4116b1ebbfc29a1fdf3a9b72b256fe4c8a794ae67526659b7e207ba1a6c4896d24f9504acc6fae6e163ac0d8c4a4b9810bc6ec024f1df9d88712f589385c7909" },
                { "hy-AM", "a51fdd763d1c07386cefcefbf5cbad971883782fef6844e22505b38e20c0ebb61c43b19ba4b2f9b26e1f88a26948be27d078e1316fd4b8fe2ec479c8b0becd50" },
                { "ia", "efc38b03dd6924374d6de9d249b42824deed7e179e90072366f063715346e83088dbfde6a408d7c95578aab99850ebdd9f9fa53133059ef461f1846eefe8e2de" },
                { "id", "ddcc0dc51aae4dae4144035d5fb4be8a4eaf2b86a5c4211a2df112839e86aca513666c81a4549eb2a7aeb0b7f2e27b2688524b64d02ed9e843727c804f1b3204" },
                { "is", "41b3c6a0bdb0991cbecb09780bacac89da7a81e5fd9117158a7eac3d981ee0e23848a8eb04b69fa4cbe9fb55feee76e99f0ad61b17d25d8ed349f306ee678031" },
                { "it", "2eb364a270a55f7e4c6e972ced49cfc9f8f378210334cf9c7b65892e017da515cddac19a3f7aabdf3a3546a0bd993eb39e8084119e92fb6bf7c164b0d0f1a1f3" },
                { "ja", "0d55c55b94305decfe755ddf896daddc434326a805dd40c8034e396069803281d3456b16ff167faff537fc2a9794519b59db092fda34e5e175c753eefd7ee188" },
                { "ka", "058e1d4ecf816659ae680f213400d60171f83508f8af217caf5312fea27464463752648a90f1fd8ec56f1372c5046958b25c1ac0efd74cc50b65352d7c51ba24" },
                { "kab", "a9acae4bf972a3d0d4401ae3b6b96c3160c1879b2c11d23e86d037ab1bc64acdb5b0c06113bd1b1dda1b2d96f230f51d27d05603f6efab87c55f76c8a63e0572" },
                { "kk", "765c1e173b0ba715cadfcb8007ba8a6e28e8ba1436ee9e0a8635a8c59093ec7d43f8e0a2448bcd832cd7995d57d4d6cb5d065565b4175230f287c25a3e82508d" },
                { "km", "5e215339204439cac0da1623524952bbbc672676da12bd1da2f28e7a45b00dc6cc11f3e20175c0cd7be06aadaacd81eef744911c2d4f5291a2432030cda34753" },
                { "kn", "13ec7e4fedda328d3a74eedd4e57241a047b9dc185e1bac6769085b3e362dc7a1af50ec45ee519290c573b9ea3f97b9e8797c4786323d393a08848a2a5572850" },
                { "ko", "7105fd16781a2dfaf694d08b77914e3be1177c1ebe84ee6487419e6de11cae115f99fced01215c841cfde77542be7fde7300c3af51fed1b9f9ab98817aa00fa5" },
                { "lij", "b2989f304c71a3a15b82b8d74c19e1a069436be3ce9ec713bea13c23237187e2e5bdd9b795727ac25a8e8939f14ee4d94b615bb454825e5734ea41a244e05456" },
                { "lt", "501388923ad775ba7bccbb94d4b018338bb3f190b1e4e38c70c59c4ec818668b9fb6e5da08f808b645ccf6e61193f7d4e15f1a45b3edf25b441b28cf887b2928" },
                { "lv", "70ddc406e5481a7457ed974d989a3b39067ef1cd9a2ffe4429f9487a3870a7ce5c4328e606fe2c2ee05fd5ead70b3d2947af745b801c0376da155a15870f4e9a" },
                { "mk", "7858c896bff49334fc26e299a38822f13e5b7b2e486c0956cab7fd01fa041bf9c6896aca4781e2afcc8687262f8d1ef29661d5c83bc407bbf94e23d1d5f2e377" },
                { "mr", "934e0e190fefd7e9d0411ef83a575a544b63ffda441130e10e7259aac8e2c6a9a3d6752f4b5bf0f024a56faf7dc901c73468fb4bdd2044684a7704a735115db1" },
                { "ms", "f667078ed3b8885380b6f1a0e8e8433d6c2b13d98272dbb70490cd7960819325823ff4fde3ede4c86d6e52ef0ff0d98c738a64b15146f0a9b7cda4fb87954119" },
                { "my", "9224feccad903096033c7df491ec76cfa5a476c2fced8ae9dd83d91b34ffee71cb7851a90a9c7287c90e8c7e363f560b66f972d6f0c2d6d7f4132a5e17978a91" },
                { "nb-NO", "bbd672a75d2b6458de753ca30e59ef77ac1e193781bfc483a93695bcbd6e53a904d59ad452e3bf82dbadd32d7f73aff8bd21cc18c150a84a82ff58759dcef9e6" },
                { "ne-NP", "453c5d8dbe81733203614b78d60c081b99061ad9e6c39a0292dbf62416fab5425ccbd359d327ae48cbac3981185da97651a62a2d99c2f9c2f37dfa06d892a4cd" },
                { "nl", "2e0d567cf0308d67fd7a405d0ee4e642f71619514da6c13524071dbd6a2da2b4be7eacd161ed339fcedc9aeb89f8a819dd79e633d7a75ea0bc038c63b022aec9" },
                { "nn-NO", "1dcf781ca6b35cc7797761aaf4c0fd8bfc243cc2c8aec6bcbd0c6caa215abd9b5d7c960cb5898799244959f6bffb881e43d79e6e78412e39d1ef0f79ba9b40f1" },
                { "oc", "64befed70b2aed150eb1d2ad09717f6661bde9c5b3a71333818d1de7515f74a877867cacea233187eeef7d14cc0841162059a05d0fbd2b005ed051cfffe1705f" },
                { "pa-IN", "51740935f0bdce51e7542ab4b2d6a82abcef6609623f48c4dd41be197294e460dd8b9dfa1d8bbd01feae5067b7f5bd41318897e68b191d78e31827a6c64ecc45" },
                { "pl", "346fcb7bc885d43b042dac460f8b7c464b88d9e656219524288a71fd9a2784c3943661c10cd7f29d5b199186916462480dd612a295156ffcebce600a696d41f9" },
                { "pt-BR", "b50d5e975b29dbb9c8951f2a7314c14387448b6716dad47615be19948d554f142559039292519694c2851c37af5cd78ff7fdb77bd4ca9636a9280f0f91e85d52" },
                { "pt-PT", "6057e060766629da221e76a5ca9aa1a5650d0ff32156a81dd520b7c8c4f5e33c6d47bfa52ba56889a81875dcd66aa995aa03e48220d3f13d045b09a450504010" },
                { "rm", "2f9536cfd1f4d4adab3be988f8334f914f3683d7c2f0a60579fb9131b937f6f9604ca71741e981c330b96f9b4c3eaaaed1e6be42d22ba637936fbd5427e58c22" },
                { "ro", "a61080e39cc65bb01bf3c853b50619c881d5bc4d5b5f111ff656fa064f9f5ead5269c7ecc4a255bbaac1856d2fd2033dfa884ea10a477aa527dc3428d44b61a8" },
                { "ru", "cb32bca0b772f5868ad1e528b88ee37f5637b929938e7b2afc96aeb41a43ad74e1962aa94e697228d74e6dcc4427866d3e1f527e9a582fdfb9674c569de46988" },
                { "sat", "7c142e2a9ffec6d2fbf613604658fc3dafca9307496fae14a2b33ae28564d6f1a9345845583c3e9a47c31bbaba3588125d936c286c1f81027d6d490e31efc8fd" },
                { "sc", "a0ced86b21ecdfb38a9739f44050a5bef4428af38ae417e5fa4f39b10083280e60f5d14d8bff9bc373d01316b0c23077cf978712c6dc305bc3e1e39393956d5a" },
                { "sco", "15e78b6af8592660f964f18c2e56b6ba962288025f76bcd6976fdf23458debce70a13b82d12ee137ab42ad955a5aa1b862c4c12fea39dab3714a7839a95a44f7" },
                { "si", "c67494d0e891c750b0b98a5182871e3975350b6dbd9c17052080c9bfe43575278733cd15bc91fd0f7c95f1e55256356b4b9ebe8affd4798ce1c6e8b443bd7bb6" },
                { "sk", "eb2d80b5eda05599c71b99e8aec5a4a7ba31b0f6136c06fe63272c37af946482a39fc1c82211cdcf98160a243f36bcca03fc2bb9f62c3f328ff50e71586ce9f3" },
                { "skr", "b1be17759e6fe98350ebd48a07f0f9a90f2025256ac2072131d9a4e5fb0e00f851bc40defb65ff6616de6b892980667553c75761f71ee7f2d4b7f9a63611e32c" },
                { "sl", "dcf1a9de4ae40ec3c900145d6561d40939c2205f2741b7911e1594e6df68f37a123793dd43504a766d3e042d0c057be9886798712c3a78894a351add2db88303" },
                { "son", "431d3614daca7fae1caa90f326fe2ac65547c3771d9a07991c3b0fcd2855392a76bb0209e86868b848ba309401416f36b1656e5158a6db16f991a729e2e4603b" },
                { "sq", "43159b2b3c415f05b326659aa9c3a85f65a2a1865a256676e52dc70ecd929e5e405a1b1efc6d26d0efcd6c81cffdba0e620d42c3eff5a1692e40e667f8268fd1" },
                { "sr", "a13b4b4067e32bc914f00fe190289198f7694ad7f2067fa9f9d6c6c663dff024cdb6b77da5b7a5035782add7950aebc5eeb467e4b62c8a155e9854f666fb22d7" },
                { "sv-SE", "02f51af225165615c863dacd7a715f69f183f10fe9723f1c062a479a14d0ceb43d368fdfa8c483a809cc2973da0c0da93ffd37274215e8009b9450a4f4654018" },
                { "szl", "c94a4c787bc7fa786289a9abcb2f85fbb4802b3c24ad4498f4be0665f6d8c9fa1f8bf31866af31fc6d38336e65bf0153c895fba66fc5f6c3fe7d13ecff4998b3" },
                { "ta", "60961c350e1453bb1bec00f4476a607c1c476e6bde431bc082eb49a538282a75160bb297b74480fefe2c1cafffd57436c2573f10d21181d6f1919b0ca01682b8" },
                { "te", "39a81aa0642ccfc96bf1f12252ab0b62b6e1de359af8ada6bc7877a245a09bb97f33e811441b8d08fbbcd42d06db727766f6a37c314387683034a1a7cf288756" },
                { "tg", "9165ba379e31c6f1b8e31a8bdd01bcc7482d5f6e6a33df82620ad7656d1625c22f7afd83c42ae74085a368c76cdfb02d804d0ac85a144cb7dbcc01905428a356" },
                { "th", "d24d7728a26a9013c3a032b15ef9578110dadb114815d7073121f5e4ea4fefeb752386a65800c13ef96c177fca75cfe7eb7d3c959a49f6f5b8a9d4667625999b" },
                { "tl", "0cfeb4f9f99ff43b26c196627e11aeb98347060321304794009cf78d0c4d2271e11d99a93f6b54d2899ad3643efb7bdeab5832513a18ee2ed58b275a7f98d467" },
                { "tr", "428aaccaae02b69e3666eba0c58d65b8724442ae8dcb2f12a03d5eea67ece262a7e834c179f4bd62cb6770edf260302934df0b87c994e2f9bfd7c79e9dc888cc" },
                { "trs", "7f792972e525e8e111eba4bfc626b0080e5a89a889e4cfe6586f67b9ad55009d6ebd22e6db08ba7962d3e942036533a7e5455c266fd6b5c447b8bac7c4399218" },
                { "uk", "b8233f86fce35e1f11d3fcbc41c0e8485d5c91068492bf5e4de1d59d4d61f17c4c1a2db66586a59aa463090c7e435342700312a9e9282682b88d230bc64f3beb" },
                { "ur", "a1c02e2e3cfd2c2afb837b43a6e9436b898084038a0a519ca8e79b90a133ee91dd9ee3646446334cb80b29a4093e612aaf0ca1c2174015ba45d07c27f02c19df" },
                { "uz", "7945d8302ea4a2950f5673149e358fc5bf151919028b719811e50984836137550bb6571d890609eae71d1c16c28d36a40cd8ba896c68aa8af5b9fe2a758f79e4" },
                { "vi", "e75867cf526eb390900767908f5932558932369685bacd4733bc6eeee9cda73870773c37544878b360e968506a6a976e3724fda53ea3aaa43412045fdf50bd53" },
                { "xh", "3f998f43e5a93622db21945e5f67e3acaa91dc91a01baa7b9fea071f0bf397c1710cb8352585eeb2cf13ab4c69b8ac86080ddef1f176e08b773593975425bcb4" },
                { "zh-CN", "4c9e05121723d1c17a8a3e8230c7234e6d11a0e6021f0c455ef0d96715999d2d629782ab8df780004ab2931fb005b740bb894fde3bf313deb4aee75895e49929" },
                { "zh-TW", "865f01b1c843bdc21a379011642ba3ad6b8f7f239396b7726ce5b5f144db45e21516acf113d8e62d7d84cfb98dbcfdbab8661da59a57af0894fc9a90b4ec02a7" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            return knownChecksums32Bit().Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
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
            return ["firefox-aurora", "firefox-aurora-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox Developer Edition.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public static string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                htmlContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                return null;
            }

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            var versions = new List<QuartetAurora>();
            var regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
            MatchCollection matches = regEx.Matches(htmlContent);
            foreach (Match match in matches)
            {
                if (match.Success)
                {
                    versions.Add(new QuartetAurora(match.Groups[1].Value));
                }
            } // foreach
            versions.Sort();
            if (versions.Count > 0)
            {
                return versions[^1].full();
            }
            else
                return null;
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
             * https://ftp.mozilla.org/pub/devedition/releases/60.0b9/SHA512SUMS
             * Common lines look like
             * "7d2caf5e18....2aa76f2  win64/en-GB/Firefox Setup 60.0b9.exe"
             */

            logger.Debug("Determining newest checksums of Firefox Developer Edition (" + languageCode + ")...");
            string sha512SumsContent;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                var client = HttpClientProvider.Provide();
                try
                {
                    var task = client.GetStringAsync(url);
                    task.Wait();
                    sha512SumsContent = task.Result;
                    if (newerVersion == currentVersion)
                    {
                        checksumsText = sha512SumsContent;
                    }
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer"
                        + " version of Firefox Developer Edition (" + languageCode + "): " + ex.Message);
                    return null;
                }
            } // else
            if (newerVersion == currentVersion)
            {
                if (cs64 == null || cs32 == null)
                {
                    fillChecksumDictionaries();
                }
                if (cs64 != null && cs32 != null
                    && cs32.TryGetValue(languageCode, out string hash32)
                    && cs64.TryGetValue(languageCode, out string hash64))
                {
                    return [hash32, hash64];
                }
            }
            var sums = new List<string>(2);
            foreach (var bits in new string[] { "32", "64" })
            {
                // look for line with the correct data
                var reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value[..128]);
            } // foreach
            // return list as array
            return [.. sums];
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private static void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32-bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = [];
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64-bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = [];
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value[..128]);
                    }
                }
            }
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
            logger.Info("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
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
                // fallback to known information
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
        /// language code for the Firefox Developer Edition version
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


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32-bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64-bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
