﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
            // https://ftp.mozilla.org/pub/firefox/releases/143.0.4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "3f0c98d1b7a283f57b256f22943530937327cabaff8108aea2d4d78828d0d4898d18f019a0fae0fb739218348d855d7c828a72a8680575dbc4985ff2922e9e04" },
                { "af", "7d220b83f982c4fadb00ee5fd6deac27abc080145bec91a9dbeb86fe8ae7afb3eee0213db4a71e4c6b547443a32338297020d09653b3d581e9200ef5786d8c3e" },
                { "an", "5859de09a3023cf4d8121c85a6be3a7c4cd65f73cc9081c1b46baffb824edbef556dfa65124498696721bd6fff444b4b4166b887d1c773757ecd20a8765cbbff" },
                { "ar", "6e6dccfd1253dea6d6482eab5155f086d8765330119a49a63ef5410825eb0d210aa775412b512eb69cc065f78a299db3a17874cdb26020f749b46c06a826a7ed" },
                { "ast", "9ba044621582868f2f15024eccb558135c7fbe617894d71aef87309e62a5214b05c14807140dcca96c9bf5e78596f2aa7bb027af479f69d4f2bb38953e769b35" },
                { "az", "4dfac8646252fd144df4f1105d30a06ba7bb75e4e2a40cf310dafb1e0ca0a8ede5b557e9600cb1192a78d59c19b27a1d2ba1188631e4574000c7a8ad1c2ef9a2" },
                { "be", "06765c70cfe810c80dc1b92ad8dca4a4e5fb7397d231bf46ad4cec33b52d76f17e1b3e7a367ab3eb6e706f72a283bbe2a028ed951a2b5888cd75fb905667575f" },
                { "bg", "6810e130cff733585130ee7fd35d4baff857a4d4533eb659739c4c5c74c8cc76c47526cb498f71bd2f11af02d07ce079d125e2ab042c9d33b7adf7c9facdb6f5" },
                { "bn", "fc274a48f9c19897b3b7a9b47f392d4aedc0febb18dbfe0a277f0185bbd8f13a505ee4b8a7ed3746d079f24baddbf91822b8ca0f5ee3002e320d913f796694e7" },
                { "br", "d106e502eda7ab48d47167ea16ed679139427843dbd7debda0fc31265d7cdf2924876573af4cd2ce58c57e1be2d093fd5adede0696b05d2f2bd16c8293c44325" },
                { "bs", "c5a5d18f51841edb5923484fc6a206c894ddee847a33e37396ab2e95b8e256e9cb725352f33d3fe0ed4b7c81b6b91222f8fdb497bcf2c3dff8d6f59793ce88db" },
                { "ca", "538f0068a7c201ab6f6efce72a715c807e15f9310d111561418067e3720264f278485dabb3f7d8a0aa20c3eb7a5c354d1f894e9f0b40b34de000b859048e2678" },
                { "cak", "5e41a5a4e2634c4a837bd0d66b3aef7d69e4dfa759838dea78239c938a17698f03769396ec7cf0a51a3304441ae2f9365d3779cb63b11e67eae05505d60cc738" },
                { "cs", "844b48d83152f31a1585ea8c23f6665271a5ee1ae29bf9cef148dfcd0e1872b6067db78cbbdecf0493b6214ef862f8740ed68e89020993130dedfb957e0bd4c9" },
                { "cy", "0beae846de84bcc24a94f21abe099a6f7d8cd784c340bd63c679d2f1373edeac871a24781bbc2e90b5ad57642bba4016aa8e9a616dda5707e6d590787517e1cd" },
                { "da", "508eb026b49b32481a5f659873cd23b857043a00999293e277002a119835d55db09fdeced88b0f593393d24d34a33bca301da16554523e06630ddaf89887582e" },
                { "de", "2776e8ee5d2f340e674cbdb82f38c3d19edd33c6383e19728d16f8104e164111712a104b9526ad5a5ff051b525c42102dc3b1866e9ed8a0ca798c6e626d83218" },
                { "dsb", "9800347ce87fc6d4986ecb7107911025390e92e53fbb782e8bb0b2ac2472b457ca6660d1ba681eae3c892ddc3f2af55033e58b9982a198e54319876f9bc8ecd5" },
                { "el", "cb73b34b5348cd0d4126711e4a43d35af8df87a87307463d41824a2b6e62d650581a1179f3ddb2bab6ab81a4917b1c84d8b659318dd18c227e95c4e1b5320ef4" },
                { "en-CA", "3c12bfe80262553ffddac0436d6d8b0d25bdab54e8ca715cd8f55a769f3de4e396d2bc6efdf72e11a3454de8d8a17422702c97b58dabc3dfaa3188ccad89fed4" },
                { "en-GB", "3f79706bb21a504b37ae9d01e21fe6296c6fb0641228edde852a403436497f45c486fa90e8f2ee91ebb5f616e44dc6403c44948e4844ebd3d2ddb5a05d915883" },
                { "en-US", "1c399ab1812eefd7fe82231515ef4030bb27969841e03c2bdfcc2c183c8bf17507716ca3273762e1aca36993da4269a032880e9fa88e7939ca3d9babb7410582" },
                { "eo", "5f4eff06903660ea4bed0319784691f49151fa486e8eb3873554f2562e7107b09c2a989ed3d90e753303ae383175cd140d28f53f55d61d678239bea41bb194f7" },
                { "es-AR", "b8e66c76db503229f58583006479e79efb66fce02f09c84095ff9c12eba24cda9129a7b1464121f2ab975c5dc02715ca38bdba78da58d174feed676c9a1cd248" },
                { "es-CL", "9ce9a5f1a93458e79cdfb775875a9670c3e53f578ac9558a88dd62c532b9fe5c9e690c925d2ff78178f88d230b5c0f913b413364c978e52275483811493e1069" },
                { "es-ES", "1ebf4ea86dac64d37ef13354f73e469a65b7612b893b4ec24cd2305814d1b52ce21f66f03e5045046f5a074bc0707e839995eee480d746266c1c44e0a10c5d95" },
                { "es-MX", "0996867316828fad69ab566c6f4fb905d4403e0563d95c37bd6f795acb0cef543f71c0857e86fdf370cde450995922250f33ecef9d097d8db165d7ae2bf1048d" },
                { "et", "3d20eec1d8d52244f206a80b4242e5c285c2fd11cceb01ffdef6353dbe6ff236ffb1e576c8ca1562084c268cbe05708694fc2d93eb7032eaf1e57ac09c6cff78" },
                { "eu", "d64de8184b8c30e78d90781ce93567287a1cd917ee842f779d04014c95e0a13c42332a4d6da9064fb83380a0a8a62acbe6709d450f625693b2db400365ec9b46" },
                { "fa", "0a947e028537fb47f7e56ac2ae12283f6d2ca287814caf1e1430a9f16d9ad2a9e8e8b911791ab63b5115094bb3470f4b6da89f6c701d369501bdc39d1d840142" },
                { "ff", "891119c67d0e52c9d2f959330b795ec1cb6a8171eac0631d6af7ef4ddbe7f11bd1cb2cc3d96873b1b7af48183c48c119b74de4eb5f2ee5f26a9d71f29b6c5902" },
                { "fi", "958c540a01aa4fe3d7c7077ab3a010139a758a598b0cac5d9421d5ae3cfa7b62186094e3750d0b5c65ca3c17bb1867dd83f2698630c7502b9f7af7aa091f004c" },
                { "fr", "159d3579d338b9117620f9712682c2126e35f33ebf91b707245e56adef62c056bd36629fc9e023bad70b63475b755d1a4f24cf2c2fbf2c4cf29b8a4109169b44" },
                { "fur", "063a084f8d5f74e7890fcdfd787c72cfea6b8a37c4cf6a208a7fe0074d07ae121dce45907ee9ab79bd349269546785cbaa4848b88ac2d20ad1ac2c854c470ca2" },
                { "fy-NL", "37ce2f4227911f93e1fc9889b1f99027fb7faec189d4548ab30417c02273eb7dd62dd30669e6a6708b95de13da2e00e9ca300b972cf29c979123c6d951fed6a4" },
                { "ga-IE", "9faaeb32243e676cc6c6e6baf62390f249a7439b10affb8caa6b9dd8165222cd806304c5b340c3e9cc7e08edd5410d5e1db9c65e3b74bc8e343db6231ea48c95" },
                { "gd", "c2e6b4b6f7fce6e3c369ccedb6c7a60cc2925a3475fedd2b2836027d3ad76239128f13120e06295054233ce51c45e9263129daa8e3ebb76267365b78f7dd70cc" },
                { "gl", "2c3a5dcc74b18945f5d22a4c4f5baaaf264d06b7a7f19840d38ea3fb87cc94a693cdc382f53b4a19f21f41ccee6279d34c80c252a6edd4d9a45f3231345ac386" },
                { "gn", "73af47a392c14867ec605bbbae8d88b7d2a885fa1f4730b0609669aea6b5398aab7bf652cf02e2ab771771f5e9d2135feac3f21016f38bacde247716fe4f7377" },
                { "gu-IN", "861890b718cd2dce14ffaf3b92401585d285b4566ffb4224e8153a98974771755888d5e1a575bad82830f2d87313b976f273eb1e3261b8ed5e91d0bb5a9c6203" },
                { "he", "3445102259d9ea5c0b5833383fe195bcbcc2132906f5a41767371d92cb94c3c959776da1e29e517d690057a7b6d488c3589fc00ca414778b9c9ae75b273c8410" },
                { "hi-IN", "c7beb639a85519497c6499c6ccd607a5336834d84f2ee1569a1cf7f1a0f99b6ed934e77f2119b2c876e586c4d47ca453e61c9199a6a84b7e7e5415936b28ae9b" },
                { "hr", "bb8d8647626ce49d53fa5ee7c685dcae74765d282ac7103a2f7450980af10e79c2ddf2c29c9cdb77548bb2c9be397a8e11ffe0478ac47e5f2951dcb5ed22fb6b" },
                { "hsb", "09525fdd3ed6e02ef3922cf53a276e2cdc7c194ab914efd746b316b68692edd659385b438f07fda61c4e480e1a33e1c50e78e09e5b888fa8a9c3beb1df58b9da" },
                { "hu", "d714947ae6d96b74ea2d21b75a55415a3398c920c3c7b8e52ed7c9909cab102d213ecbf247d8d75e1dee04bf406c66706d8f1ce026059868a96ff91755e58795" },
                { "hy-AM", "a8537f29b4c56dec95e3d3352d367f849d330446f1aad14adf9b27d410f79aaff3c96f95db103adf4973fee881f943212af7ccb82b964649f2c4b054b40cd920" },
                { "ia", "b5baccb0cee66be75053eb79d29fa13419961013a76b425db74aa2e6d702f25a4554de4d72c95d71ae90902ecdbdf1c57fcd81a11c92a13659fd3b6cff33ecd5" },
                { "id", "3452c2b7cbd331e14865a6b874030f98344e12355e419a239c81d43fd24a63ff353c10dd5c587bc88095f01e49bc5b589b2d5847a7b5199227d1f5778c9339f3" },
                { "is", "2bef8cc905f32652aca97aa1fc3fde1a8da5a31206f7aaf557f67dd676ad614eccd5b795d0368d25786900d28689039a9940107bcc2112512b9b5b5d646d535d" },
                { "it", "521028ab22b7e4f52911430efa25cbc0ed79fb0ae2f4fae930b292b604f68010ac31a2f333ca9d49bb404e7557370fac5b1df3ab1bf11a9d1700cbf0d6617654" },
                { "ja", "a4882f5e4614f87f6d54f01f4476c67b3e6ce889610073f01832a415c33d0847d58b539385c81bdeacde88ad49283b72f2db30cf7d7e171af3e16f7c2d259f07" },
                { "ka", "679138a7b7e1ee42f951da928818851a2a11ead5bf37c0b66fc6bff7b3600fcfffd75b2f864b2bcf3c0dd230fa7fe84dd7635aa226d001b3387adcf8c360ac96" },
                { "kab", "f78e4404aaef998334d1f2ee3d655dc5005f8aca65245ad0c6096a9d3d4bead96ed31ea1c571dbd121451de3f6886a0e53bc74db3d031b2d4d5bdd156be14acc" },
                { "kk", "bb38a24ba8e90a252c9d29ab1eddca43d53c297855d7497a1df61c981bc7ccede85dbd0818aba3140419314337dace3466dd02231f246038ad6de203445ad457" },
                { "km", "75f1e7bd2fbc70e2a13c168bb3691a10438bdb5283bd8526af33b121d4b6631050000e858d31aa1a309066c385628e05f1bc6cd2a5fa83b095b2b22762ebd6ab" },
                { "kn", "e67e47a054c456afff685256c24170b64bdaf8e9a435ec69bf93e18a911cf0515d7f9f53bd989b269b81cadcfd18d2790e205cc66db94b4e873c6455a7b402ce" },
                { "ko", "f863ced62f72866e3481806247c32ddcf476e4e836c8af793e9c992f0b7ad8056bebe59ad95f08b951ff831c045fa6b88d6c6e052313ea90e6e2cddd5ed3fce9" },
                { "lij", "15b0d32e489a119aeffbb8cc531fa8519f13113ef407e40cd757ed38e918bd6b5e95692e61aa45164a5dafa00670279e383054c9cf96feddf43a68f9b755d9e9" },
                { "lt", "8b55d342246571be1aa1f656aed09ac914cb600ac150f15809d5014dabf9a08b868b43b3bd840ae41bc0f5f7c0c670812bd74573e5b999d719014912b0ec7c7b" },
                { "lv", "f6f34df2583b8e3d5132ec94ad36ca1c8eee99e49ee80adadbfc31f1c09d153aaa8f4f599324f66d4075c9498808a96143ebb129e7d0afc4168dd4e4fc830d0e" },
                { "mk", "2576513af7710ec27bbeaf456a6fdc1e005d05b1ad35f4dd0736a6c64459bedc61cce328b4cbffffec735db99c8b2e1a7f5660d4ac4cbdec1d43ca451f79ed01" },
                { "mr", "3acbdfa8769e1fe50a3f9e09a68551abdae035ce272728488f57c8357fda0ae210de5614b85d89d415e3287475195dca4a740fd6666fe6cb564e1e887c2f95be" },
                { "ms", "cbb7e1ec3322b614955c905dcd741e318c213310eec7c16086bdd0da713c924ea5d823135bff7269335cc9c4ab56307fa1ed390fe446023e84294f7b2b9f8d52" },
                { "my", "91572a8af3809cff6a3f592cbd2b072f4ab0ada48bd81a72e59443c109c8cf07c7544ddde0dc8af250166e5ba4f48736562c4f163a9b41f8fcd26f9c1a7d8b99" },
                { "nb-NO", "fff483bd3114fabecbdb22852c437a4481eb3f965c059170d71f3c629b417c5c9334435d3d14c8ac67ea80ca423a079e628eea9c2203555bbf588ab4bcf7dd70" },
                { "ne-NP", "6cca84dcf286c3c2f348711b3cc266b7dc526d9611d69e152b0b57fcec0fc43f764c37669a0ebe3ab400a62d4aaeeb15260fa211cb8a7414a233777e274d7bb0" },
                { "nl", "0319ddac090db38843f95a60e7a4276ac8c92b19b25db4784e39c1a43d742994350a54b993e278f6faf8f0bc6cda083b1c81a7fa07a8299a43634ee50d682b80" },
                { "nn-NO", "ecbc6269c6e762fe53bd1aaa232af7071edf9f44d92e48c00de3550b9ad0e304034fb523971a89828f21e0eabfea7fbcb7c77602a5247005e3fb9489859f4081" },
                { "oc", "c9ec99c286cfb21c9f9865211a9f80c5f828a20f167fa0a2737a9f352b8ac245d6c8add6664b3dec03c823b7fd2d4f48b0d1b60cf2ae46fed377ca023a42bc12" },
                { "pa-IN", "18b9ea83bddf39cbf30be27ef2529bfd0b610dbf418537395c85fa13afcf070f3d27d34b94c9b9d3bc1bb8ba3465606b9a6726ab5c759183486c1a9786c7b07b" },
                { "pl", "9a9ec6ab10518aa80c28e1c5de542918e7739043441a042e3d615bd133539a3d42749f08040eeac1506ab9e3622cd65d8a2ca98c79ec9c3a9bec80a381183de5" },
                { "pt-BR", "c75dda577d92310afd11791aa88cfece719cbb9a96eaba122b0330ea14521132d3a5fec490b9c247e91b8dcf1862b709e16a50e9429d16d57121ef0c9161a705" },
                { "pt-PT", "4a4362106dac6e8e7468ba3fbcfb530ec911498e9c67425ece11761bf756fc7806c5f7784d677bbecda1b12e031f3624c618ec83c4eb28b588e0ef2f1e5ce5b9" },
                { "rm", "bdc75074c85043d7e383b8d812a9b66c59d4316317a26fc2a355055014a5f066b6cc56cf9eff1474b2e8602a87a19749472612e1f7ace6f07eec15bdd75f6cda" },
                { "ro", "466349ee163a96ae646e8259ec9ed9f80d1eb25b1fac7a311ccba72ebcf7ce91feb8d2ea2906e4fb717f7efe3dbe5efad36edccea0f32a50909f60bd4d73138c" },
                { "ru", "b45722d0d2cb1a5a0797021a54c15ee6d0f66576cb2f14fce9483bed3ef2b6a8538a11ddaee86484a937a9b9bab6e1b6e6378fcd66d30e20e31f6c703b54c424" },
                { "sat", "bf13d73c3e9f765b43782d79eacb5bd545706f6534753890e0bf0db122b13cb296c165f296ba6bc023a9b07dd4d9a843696f7d3d9879c1ef907c8556c2ccf2cc" },
                { "sc", "4a27666c2aa8c1de57e4b6b71cedfdbb75fbfc3b278a81a30f83da2baf50b9623182bb07f39c1af0fd725cc77a3a3faab54fd34cfe9448690d1b5b60ea7f70df" },
                { "sco", "a9b4263f5041b7a74a3630824ddcf6c1c7903eb6f196a2893f862b1b4df65d98358641e7c24801ae16a2ed73ffd54b3e6f9f0566649eb3f3d497b18a96eb59a8" },
                { "si", "7b1fe2c14d7d88e8fc90c77306b1a6c2e59bda687fe40b0978d8f1ba654d08baa387203218ce4229c8f0a9ec2d8aa5bf52c07a4446cbb7d5435065163c587977" },
                { "sk", "81de47a05d4e14dad5c6cf2c36860a5bc78b0568af1202ffb4326be1e0f54e06c64a80059b3e002016a4f6409e35508151bddc535dc182903966c729add406ea" },
                { "skr", "6ef688e309e480ee99c7920f4fcb787f6b653b77294929cc579f0880f1edbbc90d1ae69bb9bf6a4eed11cdd45fcb90ed749ccc2e04f9db1288a19d235c5bc178" },
                { "sl", "af4a9ecf1f6bd7249eafe4a135c8b5e0c531d649ce44cd9082c53a62bdb1fc2096f4b74b0eb943e869062be862eb3a76b9c2e2ae3c20c5db2c3bd587180344e2" },
                { "son", "33d343593d66799d402609f34f88f244e722334a67efe27b9107ca7b59448f14e0d0a6014e145c276277fd404aae653b90e0c885e2aca9da3397f984bb0788da" },
                { "sq", "9c48c4303a4bcd46ddac4ffe21ccaa0e6fdd1d5a796068cdb1485f780a2b64a7e3c6cc3c3e764c7c2edaa7d44fe30b717f2705a95e12f537574999a940c244aa" },
                { "sr", "5f8a93c07225eb874741114631215ff529ff27b2624b70b8adbabd3e09c02f01b1987a69ac473232c921d7fbccca66312062e73d30a73ffc658d4e7bbf825ab7" },
                { "sv-SE", "af6f2058759ae5aaa8b9ed9f5431ff6d3adb9c68bec22bf6e9c05246f1956f81e9daa8a0391d1e188ea182d34d779fa5aebc979af18570741700fc584e269e16" },
                { "szl", "68b83526fe02081e56a417d37b798fca003eb8b65a7ad027ceb7eff3fd3f6f4663af964b4f2ed55af0f4ca3d0db1de71c3fc492744d253cf1abe12a44cc09dfd" },
                { "ta", "5afc20705bcac43a1b4dbe6c4574954c58d1f1923ea900927179f7128c07a11e9bfbc35a947f18614a8979c0a789bc205a5831670da4ddf3f9d4c9a56c01c60f" },
                { "te", "0f6117e8144adbc7b72a81cafc29aebc2bf03faf32ec52797de756b07ab93edd0c5f10a6ecd0fc0898e33f24b34191223a5cc87ccbab62819edd026b82790279" },
                { "tg", "f4033a119ee36be97b8bd416dda1230623d884eec170d3376391a4c5a5ea6daee35d1d2f6b4422a40631ffeb8ee67ba7909c02785446ea9c1dbe3319f08dfcfb" },
                { "th", "4487f02a30858f02735bde2ee49819589e6edf69cef3d7fe12bb4c8dae327c783c3cd8ee3dd7383b5dd25522e72fb092ed8935c59eadf969dd7fe601b8f97a85" },
                { "tl", "b26424cb78f69e929a40d7e66e96a4385a2ea2fb13de1c0a32b171826243698d1d99eb5361202e7c26ce603a584cdf339a6cdb17fd6be940804a9e22f710ad61" },
                { "tr", "21e6f36309f88488891ff675e079aced363f8f06cab6dd465c9455b0e9e55949990016cf3973f34988cbf051ce1e69c109686dc9e0b5a3de10162a1490fee469" },
                { "trs", "dd03b02c52d8dfa035ecce6d9e36cbc540a5299fb6d3cd4d4f25c377e4d23e7dc2b3da5aac8085161dcb672eab3398bd7a478a5c18d55866f9da57abc6f9ede3" },
                { "uk", "b85a5425369a1f2443f1a1b48fd9335ef7140c2e810378ba1235191fab23b5365bee9dbb1604c89930b6a624e6761f6738f28ffa80d50418c70eed45f7fb6752" },
                { "ur", "1ca017ec6f9767bed237d97f016bd58988da1d6c8f95343525765883bd100019ce2ab5023353440664e49b8d4c72386bcbb790295ffb0bc1c35b7581a5ecc1df" },
                { "uz", "485e084974863febdf608bb77e34d1b017067fe4f531481ca8b546754f09c047e445e95ab396ce98997120fc59bffd6fc83cc190b619f5f696e6927af695e5f9" },
                { "vi", "2fbc32d5eaffbff2475913816f996e6676379a128d8c20657f9499f75a868c0cfde93176a7e1b7a9466cb226c23e16858e6cbd9be06f9520c4dc195a986299f8" },
                { "xh", "6a25696885ff71ec5d54811725fb84287a8007a7f4d4a2f5c8a17a1e5110d0069ee3c1da6a9b5063d8c19c67ee582b3caca597802f947fd9b08b7268b0d85b91" },
                { "zh-CN", "34aaf17056f265a3e9351728b10805fbf42e07e0490bcc8ee27107fe56b1be3c2d1f691ee6dca329c695c657931b54c75f7de7d8ddd5a4b0e193f9be3608f30e" },
                { "zh-TW", "2519df2aa408a8d7cd85a001063d29bffa0b310936be842757db227cf41db9d2bcc69c80d6258093d9bb1fe0be7cd49d3e3cad473a1fa001d31d9c0cbbb5285a" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/143.0.4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "6f4f9252621969b96e2edb83dfd6e6eafd8fc5b7463ca5c17de6d35379d5a3ee28413c7c671ccec36bc3a41a4dfd5f1d1e01545fa341694a7b728838ab9cad37" },
                { "af", "e15358d401e73de9b4c1955737bb311dfa8fe3c6d3a3ddfda266a4bbafd88d2f834b401253272b0b002f275991f8050ec63719c0ea5f6a3ba4655e622438f202" },
                { "an", "2e8c021b986e0350e74520b98c6e0dacde966aa5f50a4d5bafb1ab35c81a241f36b69a978140b7f651df9e3995c07ad462978cc67ec24d9f21f32a6e8786349f" },
                { "ar", "8396944d9afc95753badb141f38a22991b086354b9f7e104710eafaa3aa65be166a84519d6d89e65ae930c872cfaf76c7692126a6aeee11ec60d6a31fb0b63f6" },
                { "ast", "bc943ade2c06024e05d121d2ecddd01ba008a3925074fa224f99914db7c883ea5800c203e4310ce5aa248975abd835aab6c5efcc4fc9bce7fd0311b139d41431" },
                { "az", "fd34277079186c471e49ae03c75688e20fa904fcd46be12e196884716a9ba0f05c80c1ed74a1e24217b959182edd723035999da377d1e37dbc125c82a3dd051a" },
                { "be", "72f4b3c19fe6bfec2415782435ce016b09cc5cefb0c7ee7ce9535c7f8f40205cdf1dd4373c31ac1720c4fc29c596e92a04bf7a40a7432d5447ea4e767acc026e" },
                { "bg", "68d8402cc1b8d65c9c8cb1c53d737af45b31102069cdce35460c5a3d5d7304907f2bdf4312379ed44a1dc19553b94863e9d7f59e5c16670396f11e6a4b859f23" },
                { "bn", "6dcb749cc49eaf42230056110345720a6070e1d9294aa86a2c5e2050e02fcaf714d6d0579050fce88f10ba9bba049ab1c8d4ab1ebc98c1f43038fd5d49c431ab" },
                { "br", "b538fff79071d01ac9e6f8595cee1a1fb155112554bace7ade31b2f6fec2a450c7de8ad6669f49eb882b0495bbf238be1fd3459cfc44f31acd66dd01814dfd9b" },
                { "bs", "f728d74e520744ffdd18ffea027c2c60af512303aa460bf6ab1a4735c3b48ccc1b3178b256564c08d2a7eb7e1a3b4a9911a9211cd0f6c314cb339a95c1844ee4" },
                { "ca", "8bbbf06c96afe60f00108dd52c710c5c370d1fa870dcebf3308ba39420cceb23bde2ec065cc75ed391e255858b31618878ee664eff1977f66b9fde8ba12476ea" },
                { "cak", "fc4e5a564c221fa2c9e9c9993f97650f9607fe6c2e976a94dba8fc80525de74bb587d385f720d43e3804aed724eba58467f251f0c166799d7560e8bbf29d58bf" },
                { "cs", "3d6d99a8e36de099535c46f8e3bf2d735516829603f0aaae9d6695c525c6873865cf27344a950e9e07592b3e3c98ac81c1c65f3b159326c1e70be10fb3c12ff9" },
                { "cy", "8ef9b6a5cd521e0f9487d7893d867a7fa90674c22f877bc21b52803cfb3aeda55cc1b241ae3dfc1fbfbfc52ed49fc3e089db484d8d3016089748f70057d6a662" },
                { "da", "a0c6b2e834da4c0fb3059c20d0bf8d6ac2d72ae67af5da44b6c8e65db12c3be30fbf00ec06d6d2c0e09d57cf2a42f2503f8ed080209dbf66643c5a092006f658" },
                { "de", "7256ce5ff74d5b02846a2532fd7a875aef3a3787f0023708ee347feb5cb53a7316fc91f9f15c5e08ff1b91d201ee1cdf676fddbc18902cca3ffa51c7e6ca55ac" },
                { "dsb", "e802544f86018d99bcea825d4ac10f094f10b53c2d9217f00d2fc38d954fcb01ec6063c96cee74829bac3aaaae6d7d86a91bad1e5d1cb79a1826aab0da4bf0fa" },
                { "el", "1b416503b59160526f227cd855c909ddfc9487543ff6d3c90938eec566f71ac4e49898a73a7a414850ee98455f75a5edd8dad527c092bab501e1f28e9c4ddd7c" },
                { "en-CA", "5a90b052a362e18207d41705d9c4928eeac6d8ca643b0180c48f5b2bcf69b9a2d177202c2db5be9ead180d72de33c35aabe9990ecdf4313e19fe9d2249aa9d4e" },
                { "en-GB", "fc2ec482f0434185e0549def27df04c2e0bad0aeae3956481e0983f9dabf2c6c08f9ca1874d42ee48e8d2cd0ebb6c63b40e8221b787046391734d356511e1ca2" },
                { "en-US", "ddbba0b91847ba3370ca330c7232f226b7b6e42cef90998df3db36d9c6b39881b1b419a5b8fa71d7a1e84ca115ca522b9177d08d4a73746189718a6794cd4266" },
                { "eo", "4128efcdd68f6963af66a9cf85e037f22f699441653baff29c92382740da5009cd40686e5e13403926e97f8c00ff8c6a09558fb9eaebb978e4625aeee2fd5d18" },
                { "es-AR", "b8491e637b333436e7067c61cf2819a7917e90b21fe1c0f7137a4e331c0724b4f46ade8911a068b84b35eb3d0ab990abccb6b8292d28de4b32a9fb43b35a5046" },
                { "es-CL", "988c300003c8daea56e7dd90ded10dd84e55a417d88f82ad8a09f483e00fcecf104d793778579476c6439464d80f9be81742679e7e68fe288c1329f929e6c41b" },
                { "es-ES", "2ce52259dfb3e012248a4bccf84eae377490d00a56d9f8b5cd4fcd5cf29bf9731ef59a11c20de2f44660e887a0fe1f53fb9c32ad7e939e7fcef69ba043838059" },
                { "es-MX", "60b275de2a035c29eab7a0687091a438568bdaa7ff25e43731d00e17638a593ca3429fabaa30b3ce64f8faece292a610bf664326cdf45c1f88b2e6ce4308fb5d" },
                { "et", "bdea9db7f1e70952b3a40cf0aae07747913ffd0b3926be2f203e42daebbbe0f995246ef68e0a842446581af03b4e87320992569e06548109a7f933c07bf072ab" },
                { "eu", "03d5997c6d0e5c64489787dc6a55d06fbc8b9032e8bcb71bf830239fc48999ad913d3331a54813cafd810d98b2466e9c32216bfeb08a6fe367a014fdae757640" },
                { "fa", "f2fc791d171fccb47284a75db9d4b499128cc74b805be69269eded8e63647c925ae52c992b0d9f0c24b93cf08063396ff990868c1b7f85c6d467783c930fa442" },
                { "ff", "84ffef66508dac6cd9b79dc909fa397106a90e9109e6451a45edbc7e437a33f252bc60bfab0c65cee5e2e07e0146561f344b55db14b0abb839fa992412b738bf" },
                { "fi", "aa23861db2b765e2eedc433d1cc5c40b43d926de6090cea850f765867b475d8703d4aa19907a131a6ef5484dd93b3537ba62fd91b187f98c612c5fe79b7021ac" },
                { "fr", "52744b1a40e68128ff798fced67e992c4b3d96307da6827ff46a1fb70e0d2c40171d41e9a385f109412538b7253501f1da8ee50f6af0b323059aeb378edb0604" },
                { "fur", "8c8dee4ff95c2493e0eb9105d7913bd6e00b5adc7bb2fd1cb3266ce27daf86a5973586b7c020b750aceab605be131b4dc8da4a361f30f0a1d7bfd64bb1680615" },
                { "fy-NL", "d7d1b3eeb8947775945f1ca3efb2eb777841f914a8701f819c31ba9152a7f17d194c5f2886e9947a50139404dd048c47cd7f7a945f289e28a2f77431c404d60a" },
                { "ga-IE", "01a7b43614e4880f35362dcd292d34f49230f2bbd42a152953f5172eac5172b1b90b2210b185dbb5f22c89466c5b59c68d33317e9da2f6ee06f82d81d97b83eb" },
                { "gd", "024b208af7eded98012bedf2ca33498b189dabf98e6808c37176c3a431fce7c96923894f0d094024c3e94628144b20e1e12a87f8b2626095573dda8f30785838" },
                { "gl", "754f54f7771358c375b8e040588a19613a0b6b314b95bd865968b7e08ea21971ad9b0f211dfd7f3596989c82858362a8c3362a5ca015c042536d974493cf1228" },
                { "gn", "42075bd932a479303aef6b1c7f80528b4cb2adf1c024a73b1dc88c3deabe6c47e3729062f036be947b2b0054d3e727a5390d331ec11654b4354e0c703ff1391a" },
                { "gu-IN", "2767674b3a592f8b9a6b90d0b87f2034657ee52121e2b5b94bfa963151188e1160def051b766db333eded1b803ecee50310b893da06cceb7a484f0451d85ee62" },
                { "he", "a5f5570278b0f18f31f6913399693b3b52b6dc625fa9bbf47d7d0feeaf0355221913999d889d30eeeb901d59242557e749e5e9100549d95f5a069973097748d7" },
                { "hi-IN", "674e7394147f979ec69a9ba0df8e2c059281fe367191bfeff35083f6a8357a8c780b77e5d5a377128875630a177019111e8ed9d8d74dc911b77bc8b1d779b65f" },
                { "hr", "ad1a3babad20e2c4c122f629be03ddbb9f307c883fa660536e19a104bb1625d3192bc81871ab393a681ffa5d885ee417ee942edc932e6877809c12fb2c8ee7d1" },
                { "hsb", "1f99fc26a94665c21d61909d6f03598b0b68fcfd1f8292e0db16676572fc37b1b4a2134b35a9edc0bb678c6e4db0d2894a6b4d1a9e7121885874b709f12e1e94" },
                { "hu", "b9ce15d1055255684ed72deb05b32725244efe8b008c15daf6f9a586864d00d2c1ad2748f0e19025b03f90662d2bc54217c81f24c88d156771dabb59ce838419" },
                { "hy-AM", "9d4bca7b412838615bf3db7634a8eefd14a6a8776e13b4b4f558f09ec30bec61e0dfcefacdce927b9effe8738c046d127526244e6c866c63aa9ae46a220d344e" },
                { "ia", "7770b424e80ac11e74091a802dcb8d18640dc0c2417e74d94faa0569908e9f07919067a76d2d3cc18bd7898a6c6b6bbb00bc897b002864fcaa93e716ac9f0d16" },
                { "id", "f518f458b8b5371cb36ea92da34bcedb199ec2b3ab3dc35fc537957d34706ef6c206d3b0a4b95a49570c5c9560e4d1eb2742556ca47dcb9f454523a02763f15d" },
                { "is", "0525bd4be15ad8430397ba07d64fe58636ffac1a03c796aeab127fb25b37ff4569c17db9b55c4ad3793ddd0415ed037633e619c0727aada337325e3f841a3d6d" },
                { "it", "a5277e88afe04885180cbb49ed163018f101441b55994e2d7877c06afb2fab3869dba191065c34242a1b34cabd984c3cde611db16b15daa62e8fd608969ae8a7" },
                { "ja", "d17ac06d79079fe948625563164a6e524f1b3f43df93ec1beeb310277d8901bdd13b0bb6fc73b932b91415f5ab772f9b9f6e024b53c128b89598666c9678a7ab" },
                { "ka", "ad7f69de34ee12137370914d8127838ba91e802d50f7d8f88f890b56de5fb410aeb001d6ae42b439a950f6c3995f1bc5d7cc4f03c6723ea5fe2260bc3bc5c312" },
                { "kab", "c79254a085e5cbddca9e8e397418a7d459f0a822442d223ae1dd082ffda1a45d0d28ec3fa2d002537d8bb19bfb88ae3092b943a82a1e200ab491c1c68931c801" },
                { "kk", "72a5ecc43b6ec6011d82f1fd2de002967b55e50f7787033846010322f777cd399a22fece79cb5b0eee0e0979d2941ca1b6b79d5d18841574d1f916cbb7794192" },
                { "km", "67b34e541d2e6dc65aa396684818431e83d6e3181e5c7711ed1609fc41aaa1c21298029192ad769803565531065553876312a41f90a354383bb536923f94ce07" },
                { "kn", "fbcf51d3c07c16cc4f2acbc9a417f9cae22a8dd4e01567a322102ff52d4aa80e36399a403791562052b6ee91580db63c741d355ee5665f8009c35b7d5f7b0730" },
                { "ko", "16b4fa185966a916bcf8b0291f806518910afd51bf30f0156ecdf357e3ebf84525bdffda16397a1e75cd50a700f1d1af9ae43ea38b766eb4ef554d6854c60a56" },
                { "lij", "9ccec969a7bc6dbf1aae8dfd765c361dc02b541a20e5e55d823827c40a8d8da23e85839f0cedac058ebfdc7084a6199c5567850c4f822aee6cbc9f4b4d9badd3" },
                { "lt", "e0f11ebe46d28b809fb72505cb45b9c6d7b01120fcbb96c5f456f4e7425aa071587f182ccb82794241637a09a634aa5ee90df9faabeccd469b0e0599ef5dd5bb" },
                { "lv", "95dd5a97441bd525d3e945e51b662a75075bfb712339e24834b0e59960159b56b82b2149af4302384e6aa73652f3dade91a0eb81357202fcbc331ef2592c87de" },
                { "mk", "715539c730f5aa23d96265ce7ccdf7b78dbc00d08f116a76652ec714b672374af711cd9fb4c99349f631540c6f7cc18f2603a5d44c197d4bd551e62696224d3c" },
                { "mr", "1dac0253341e1f02c01dce8e21321cd3314b207dca83f5d3f48e6fad58ddc533ca14347580e8299eddee2724ec84e05b124806384b2fb3cb00a9a201f6d92a24" },
                { "ms", "43dc139b9d51096fcc2a5eb0fdadec628f6824370739ed09fc51b03f9ae7a08498606dc00fe9588211a506d0c2d7589e0125f6ffd4be4187d671d0e33e090ae8" },
                { "my", "fe68d657159cb414500200a712e2271948c3db62748ad69da2e57b1b6bb1db8cab16a977a049752eae79e34299fa1eabe443f48572a2948f2ff3435196402c64" },
                { "nb-NO", "4b716ea3c87babd6e1805f9809aad37c45b89c8fb966b43fbe37032245b72695da0fffe945eba24e540a2bb2c26bf4bcdfecedd06ec195aa2fbf13c7e7c5c77a" },
                { "ne-NP", "0e5dea2c95953996d58a828fa67cb0fac485ad1e0b6c442020047df0ca10989f804a383f2cf2c9e77f43d740e7c0f81432e8c3451564da55cffe519b05e76fc1" },
                { "nl", "95195596a1369db680d1b1927072615494eafaa8d570ea465439dd4e304371985ff0d53ea1fd22cfcc0055c67b5ac0b2037583f849c81a8d45bc1ca1d7e59f54" },
                { "nn-NO", "7151b9c635b5d6c30899a468bc7badfd1145fffd3e3189fca9175d5457bb6924161f0dec9f7f617721a7ac43457d6663cd5f62ed07cfadb4e5b7c578513c7768" },
                { "oc", "e0f7e15cd7b4c0c6cf2f2017f47626bf3f155aeb6220d343e24bf123882f08d68bf5eeb60803b468d87f168f381d72d7d179f4fa3ad95751272db33598bfef6b" },
                { "pa-IN", "0434ec86a1be293f5ba9a214a84f9b79919ccf232475c97c3c2f1ec70852e4cc5ae7c1568478f112b7acf3e0f4a0ac0a9f93eef79800f261b3f725342d1d0985" },
                { "pl", "9d8e1f31c8eb57c6ec4df12073afafa57f6e3e7e202f6e7cb09d487eca80d2712a1340d0a2f1c48bde7b16f4052c9d7ed5068e2800f8f69ef9f22f743edee55c" },
                { "pt-BR", "b7936034bb45b3a1b32b495e0d54e8acd9597a27903e6719002a7337ff37bbbb3178cfcfe8af532561ed355bbf714cffed64de3ea66563be984732db9a6bcfa2" },
                { "pt-PT", "bb487a0dd805c78e02bcefe5bd054442cf90bc1dee66bc569491a4b5381d02c33c4ee163498ffd12641914c06ee8e45682695d1ceb4cdbd22b27a198cf5240b0" },
                { "rm", "c25c5dd7b9b86ea6184533b908d8945db2885fc2314fff114b9c238a6be2b5bbc0479a185ee167a82e8eae687b5c822eae0a8bbcc212a21a4226c9c04e7386c1" },
                { "ro", "3349e9b5673eeff7396e0fa543bf851da55197d128b75afca4ae6bd4932e4ff41ee48dc0d8a92d147b10918aecb8f5f3688d205b86ee7691b1a75bb8c5356648" },
                { "ru", "9ec59b85e008c8c2932b5c8ea0a5db3f990e9c320691041c10a09d7eb2701e36ffec1f8ae22ce9dc8b68df5ece43071c8ec4ced964f760135a9d70b407af1a6a" },
                { "sat", "fae601ed9cfe4de2cb55b22de1b5371fbb03ada217425b7ca1485857ddd84b9ddf51483de8c0efead2d1e160237ccdb0fd88ad07b490b1f24c9dc3dea72132a6" },
                { "sc", "a01d614f912e29f88d4bb237a9bb3906103b657d48d1b529ac679d464a23853a555f6891ef69712ae1612b51a61118b4597b7cce299b127b3a74c6313c95ca9e" },
                { "sco", "de30f3dffd698016d78be479f5983640c5ed5cf34b18f157a63516f2ba9e187df8e36c8f0a037503f41c6cc5ca7e5f86c450f032196dd10dec60c0a40a0c241d" },
                { "si", "83c547dbcfb1d107050c69f6863033876ec3193ed166e512d114a5888ad7e161112ae091976425b41bf6416865d8c90bf5f8b599d248b181eab87b2c7ce5e552" },
                { "sk", "0371e11427223c75a41391ecee1f6a44f7a6563a99b850ff73f27cf53ebb61790f2e23e794afca44efa4286105bc49b3e5c6df19c508c8048aad7e77fc012057" },
                { "skr", "c9f7980ccc9ca1d1b27ba20d5fe21b24e49530aec63d41e6fca46ce405c4c44ee990ea43d0d4b6c193fefd6495656604cdcc8771dab0384bbeeb089f3ebbf3cf" },
                { "sl", "9e6cd07535b113a27fb4ca4abe1c760ac72251c820513a444160fc10c28e45b6325b5ff55e14b809565bc2ba7f7e699eb13c958b047adf3e7d3fa0a52f2b9e6d" },
                { "son", "e55397be730f7c76148edf7181f04d2d75726fb237d8cb11260b6bddacb83726203fca9b81fcce16b344a43760332ed47c7021339196c86f1fae07ea043eefb9" },
                { "sq", "fcb77ff1dcd3ccaa1476183e2b1946b58ba2bcf43ecdea758b9071d48e673242e2316f5338a19c72363a0e5d564b9dd97ad24d1da32dd3c26bbad06e01018580" },
                { "sr", "c26d37565c86065d42d318b1f09e2f3d6cfcb9b5ffc3216a9a18f8802a3b7ad9579c6d7578ddb81b62a22b331ce14ca3f947c3fcf0a558368b86095f9647baa1" },
                { "sv-SE", "e9fd8dac689e18c79340e48e494bea5a3b960299af2498a4a5d5ed822b2acf2161145f56bccd23199123fe9f4e4dab012320718416815585252c790b810ebea5" },
                { "szl", "02ed96a8287544d9766f5f8cec17f96c1ce30badc1217ac2c4dffdd6283cceb54308aee3505d2ed7f4ffea3de16a05f0806c11d3747989c79c72f5c8b4a7fb3c" },
                { "ta", "dda3756b2228250b146dcd9e95da065e7826700f9b40c920da31e8201f558b9f155417f68c6fce172f02b813ceed7096082e3899f5ee1cf2aa6d47d340749ccb" },
                { "te", "99f24ab990f19ee53b127a86431307725348f3f41d0096c0a05396973de462f8490cedafbbb5aee8f858cb7b9f20df7306373282c82d33c9811c47e99a73f881" },
                { "tg", "32940b9ca4e46d5346b6976a273618a7d5419edfc35652c170bfc52ef7839181a49c01987955a88741b41a6fac66a82d3eef38e9d63959f6d73b12665718d2b5" },
                { "th", "f5f2ccabcb508f80c67a60eb040f8fe8a3364ab3c8773eea0823375c8e4b1babc7a631175be06b50e151867f915ee3792cdec312cc7e50762b7cdb5e534dec36" },
                { "tl", "9ae749c1b74155e8aba9ba3d8c2a1154240b63e0c72187b3ff0b6247f42948e5a900f2f9e501849b358aa81d8498211da538ba219231c34b4ba57323a74c35e3" },
                { "tr", "41ba06c060c819982dab6425820d160195cae562027ae9558b756d6dcce18dff5fc1e94a0aaaee1aeec1e875c20fd60c2995c2e6d07a8bc1fcc8ec6f57378bdf" },
                { "trs", "1d2a348be647c285712df35188529a697fa2a59e278db84e3c336616398f1e927c014b468d5e87e0245ddb7e724dca0f81d26bf403e80fc76bb196499d2ced32" },
                { "uk", "351a3f5b32f6c10616b097f1034a87fde323cc9ae77733cb1b53828963116046090abb7d2031f586b038a2412d3e0376c2f91590a5aa4b25222c5d10b38e7453" },
                { "ur", "649cc43e4e80a665a3a6d11094734447c819a0cfb6fe5220877504bee2bcf8a6a8add230f737e11d8c9b3c4cc99a4883c54621542d865ba7a6e533b31399084c" },
                { "uz", "6f7c481afee3bc7fa29f4e78c65c0f1e9f5b40883f96387dac25dc0dca21b9f1dee8eed996a74385f4c9246044f688c3f68ec3f79cfb2771b779f74a5a1f7125" },
                { "vi", "9d0b01cd3c0087b8acf8df11dcedb4faa6e7ebd5b7897ed7240e6f1febe515b9329df2def45203d70490707c12360d0ae86483b002289dd13454177f5b5f76ad" },
                { "xh", "b721b91655d5998174ca25c6b29654ab521b8d5eb4297843f36b0d8279a1274493431bcf2deed689eac6d87b3ccc66ffd533621320550d507ceacef69aed28e9" },
                { "zh-CN", "c8fbfe234154ba396a9d112b1612246b925c2cc1948efd63cd00f5d43bfe01e8ba9b27b9b7c215e6a24a2216e794dd09d21882d0cb85f1c82ccfb5fd48232ace" },
                { "zh-TW", "18bfcbb7ed2a1e28a48c3497f77160726d11524b40cc1884dd1ac864b6293282642a0f1bdfa8097868f4a32ebada8088f6a3b4f5991b08af53cc3d5ef79df0b3" }
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
            const string knownVersion = "143.0.4";
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
