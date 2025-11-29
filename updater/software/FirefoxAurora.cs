/*
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
        private const string currentVersion = "146.0b9";


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
            // https://ftp.mozilla.org/pub/devedition/releases/146.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "39670098e46f3a1b13c3aad4aed3623305dc126542572c6b3900eb2569dfe4dd758742bfc7759ffdf72453d217ebeba15684c4449cd8f97d630b7926a3730e35" },
                { "af", "5c5fa5b4e4aa7911a978a0b87b533deff2d885a03384aec3ef2f62111dba7e0fb44f7a908a259456e48404d5adfe2ea7dd96ca12a3f1a3b5a34df16610282ac7" },
                { "an", "6db3242a61e8620398fe57d76caf323f86f06a874cd04fa6694815054cde899ff1dc4c491c9d6ebabefee07b24c7507b2da6228663e5da71e62aa902cefc2451" },
                { "ar", "5fbc1ae3b35ed489038f2bc8ab622d912cc2da8ee76a59c265b2c0257762ec695fd8f02800b937928d7fef37f0994341e75277826965ceb4387313fac9b889c2" },
                { "ast", "500f6bd1bcb4a2bbd8516f17d6a1707d18ecc952fc41c4c4a2b0b03ea49e56ee7109f2f72935ae66b5539ef392ea5b16e3edb775a15589bd6c63fa93049d6a41" },
                { "az", "3a5f101296221f1ece6e78fb7d87c2d559ce271238eb18fe63ebb2c64731b44280fe596f6209558f9e96f201d95f6275cf12c5b6ff3df799f9f8e6936ed0e28a" },
                { "be", "1bea9447d6aa00fb85c6c60894e67a4e3d2b6d1b8a534cf0dbfb8fa3bea71687b62d940c1aab884d6b4a1b39dec9a9a480dbacad019d807d4fb3d6a175da3a46" },
                { "bg", "3abdcab24a4acd764a188a375abfb2c52afb90751d031c6bb05a9fd656335d92710f8f326a12162db6b123e61ffb8ee76a77bc7a83c6af5918e643f4a9da0967" },
                { "bn", "d9776e12fe15216fd6edaa2cd2e10395b79bd8c8e410a1ef67b1197a9587531d580ab22b1e2f3618c540a20cc3168336e80777b97dac0115b986d6b8ef3d8077" },
                { "br", "d6c2a31f0e922287b83a308bde13194683945e4133d85cbd97bc495a81f3c2a10d748bacade054dc722ad4f53ae23e8f804cd91d65a711bfcfac3b17fa62ecb7" },
                { "bs", "ce68faa1eefd663acd10a415be1388bc09e7ff7b05a8ca7f80b67a85efd104715b7795a268551a3186b878986ea94568141f140986bb44148a15db99da940a21" },
                { "ca", "623d089c710ac1558e3eb82d14dd45304632454d5d8091f4b77124c4bae42b26360c5e8a93f7f5b4c1510412e72b1566d83f8d95f73c2c9f51ca8f87c5efcfef" },
                { "cak", "cbe4e842e638c9bc9b54892f2b5b90ebdf0f35a4d937f8ce440c85e19e3a5d5095de3dece44e1de2658034dffdd1f36b8c37bf4f8a965f8216591441e5c49ef5" },
                { "cs", "fcf2b38eddf503860b3f0bcca95635af3cd128dd2605af68f53a6c2c0f6930a61e6d3e0080fb99380dc27a9c8a0c12edfb0676f608c30a31dadddbbe7b9851f9" },
                { "cy", "d8e716164d79a689594239ab8363ae521ed7efddeb26c1de8d5abfe57a8f7d7ec161f017e679c605d6ff90a185aa2f103795cf0f98e4c0468669556ade699cf4" },
                { "da", "c0d301407cca7c135258a75f90efbdf13a301a7fcf5abfdc1f813cd9930de59f502d9b56f818347eda86b0efeff4c1d70e5cc805ee35c91e547a1601ced2b0a3" },
                { "de", "d90e22c986c23d72318e9c4b8f27da18eb0d9a487dcbf304156ea3b4c7a8f05a6b068c118728f4e867abe2055bd9472713cad52d109483a457d68f9735363a7f" },
                { "dsb", "5375aec10fcae8140d31dafdb7268c0a836ac733647087486f384e0ad61a26f775161a9de4cc92666219418880bea47dd85ff3e0b8cd3eeb2bc6454466657d5b" },
                { "el", "9dd6829a9e6c3e5b20c5812de8267fa84c1fe6e3a6e86052bb4e8a35b49b0ee4ab61fd43478ec75df41bd0f4a628a7a301bc9d6b3ff0280c63d60a3c00c5d410" },
                { "en-CA", "701db7d1d374d1f8fbb088b04a2f86c90ae17064bed0a74432bc3b7c8ebda9c4eff1da51490ced0df56a093c3032ff16157825cfc2abc711b96455206d3b89be" },
                { "en-GB", "f9185dbe5c3221e30de07b6bd26e126f5acda17052f4cc8a57eadf7cc3d0dac6c60b18cb4898162a1d1507993b32e90fb000c6bfed3d25a1fd33778ef8f7d23d" },
                { "en-US", "c66eb98e2e9ebd47d92ec8288cd91e708e4c0d5bc08c643f93530c5314261782697170f19517da40f09ffbed6a13fcf0ba94dee5b43a86f537debdf5e9814bec" },
                { "eo", "0921d722afd4d0e80362c74b496814a100e10dc8600ac54e4f9daecdc8e4ea7d6665daf8d0efa1c84ea567d3b686410dca81ff03d158bb00ee17363f1c8ff931" },
                { "es-AR", "e8837a2669fba6b5280364f70cd656af72b7be71108658b3c54326af5cf5eb0f9340ca22085f55f379499b5765373d64c0f11e426c0d1366e5c7f579cb90f402" },
                { "es-CL", "f3dea2d4f0be5d3de5dd898f70e66b5de3b70b8bcd44503f2f743ce69503a34e6aaa286b179e89a4afac95001b88d6d38ca20a313410046542ed78beca746564" },
                { "es-ES", "85fe1bc474f5e905fce89ca69be9201d288e9cc10ec7ee3b083eab40e44eb4dbef2e7bff6f7e2797a03f779c100e3267ebb1279ff62c07fc7bd46fdef1fce81d" },
                { "es-MX", "d13000c91074b7c8c463f93081b03d0dde533ac795bda933645977f33cb07744926a72840a74fdad8e879db08ce0cb00b0396c4abd98c470b33bba4ad43ca7f8" },
                { "et", "c8cf9f74927336f1b0a80f4e178556699a2cd735fed4ffb07fcbc694642a8c3dc553b8eeb21e37eca2fe10426a8311cdc2ec2719d97ecf89dece3a46cf0b4d2a" },
                { "eu", "e8bf9dd4f716b7f350210b5ea71cf9fabb9518d90d5646f5dd99d8016f5dbbb9c9f1b4d2b366ae512f8e9411cc66ea9bdc0dcf0c89cabb7071a365a6fad21259" },
                { "fa", "33915bc46b875471bd8b7045c0867d29a90e0eafbec8825c172b3bf0845f8b20d898ed410e8e71771cf873392a481d2b3d6f85f02fa24e174de1f1f9dd6e2105" },
                { "ff", "d7e54a989ae714ecaef98278f7c4187b1c102840d84bddade984754061ec3224153abd9e384f59897c7c7f4c70663135da7908f51d3cee19821ecb61cac6bdfa" },
                { "fi", "0a8593a3fc6bbf9b36e90da1e4a38f54c47e172ac2e4a2d50a39d103718ab7d3746ac183a8e1359b3e2e213d7ca75e4e0a9bd9c3904b665fb458f38f9cf6492f" },
                { "fr", "a3ca36601fe4669f88a6117e5715112c33b058fab6a64bb52761930ceb9bd3248e4cf860a78737bc0cba37ad455c61ea6ebe97267b0be859f920c13a253e3a16" },
                { "fur", "a7c83c6eadab292919c28e200c5739e63024a9fc1544098d07bd088aad8531250423475dfd22dd37510ab3d94e99d8b24a4df1ab350cdd8acef0c0763124993d" },
                { "fy-NL", "c6751efcf37425a598faeefa59f63cc27943fe96e3bdd0cab08243c076f42c00f89c8f2eea5b73acd3dd2014e1dac1c910d00c59ad1f4b2f8569c6c6cc1eccad" },
                { "ga-IE", "a101b082ea589f3d695a592a6589fcd086989088dcc1bb866271b539947ff3aea0ab3c3cc8391f711427674aa241468fe878c10e7093e9e84b9526e45098b9bb" },
                { "gd", "795be35f4d0edd89b935efe6c656454e16632d51bae360c82b3504b0226396d3d5d377188b590f5dd55cd28bb47f7411a282fa2ea0970c2c490ac51ae098537d" },
                { "gl", "de8c831f2702a4df8cd21c6ba4b8ad56e6c261c2efd388dbace7a186d4c3e74082e6e5c0439200ffe59bd0fd2a7e0bc20e1a50f31efc59ae2e275a3d32977971" },
                { "gn", "22d5c2dc4b32645518d09987ee2f6afefd59b67f8627e7c48dbf36e11185c6a79df3aa06a66ea04e02f1b66491b1f5172aed32742a0890f1edec580b9b8ceaab" },
                { "gu-IN", "6501a33bc328c680f1c303592cd440d2860226fbd7b7686efb73a7ac059b451ea170fcb70c4eedca797fd87bd8b4e5439edd1390d90ce31233ad7394d8a6b0ce" },
                { "he", "d307a358101e082e6ac877a98c9917c777341700ae315972bed86f20f0ca4b2a1887cfb756da52846780b470751530b7cb8a428f228d9b990dbcaa0fa17c5c79" },
                { "hi-IN", "def5f4b13d282bca0faeb3ac6ad6c7eff3456f3bc4834d846bccb96fc899f82e2631c68cebb8b66a4f7b3772be5f69c2e13601889fb5b8417452b13cb1fefbf5" },
                { "hr", "c7751b4970e263a8a972590a9afef2d60a9d72036d3768d63ec8ecfc8dfdd5b7d62aa4b5bb471beb028ea65e2a0e5d94132c9652f09b22becfdaab1b39b62600" },
                { "hsb", "61e5d2139fe6f6cbca35ee61c576d203cfdb02e2fd4f65abb8bad06fc713eef79cd712ed2cd298bbdb769d297dd5a74218a33205f61bf3b814135a009720ecb2" },
                { "hu", "ea477279bb812fb9d116a93b557c11d77e5547aed5bd2bcd611a45b047ac246f5211316803b2fec8a85154a96e4e19892250daa22ba787cc68476cdaf69964ce" },
                { "hy-AM", "615f0678650570035c6fa2c02ffbb0f70391c41e66375a86a9358ed2a25367f4e949226d547eaf03c5d91e7777c49408af86fee04023fd83c7cd5d23b5429537" },
                { "ia", "1fde2fec8060f3cd2bc2990d956df95d008c6aadfc4b8cc06a7436f68749989257f442d94a574c9c81ab78c45e39a8946f8d2e21a9c8f885044bbf250fac883f" },
                { "id", "7fc8b862b59033b4b0b2f73474d043ff0293e4ce1e0c69c85e7c60f94359a8d116b1a3b7da7d2036db8b1fc074bc79bac28a8d592381858a4c8041a42c22cde9" },
                { "is", "e0c362a3779e2f571a5c5e47c0e3a61abb804bf363548786f8f81da1edce2931926a5eaabd1b2708f1dd5bcc659737b1b633101d815176aa9b4ef051fd163258" },
                { "it", "0c9f951ca1df988b187cf3d9876c6ae1e785c252962be42146475a0c9e40b8630eab75351a53bda69c485dfda5467d7d13ca3c31122279eaa6195f2ebf439690" },
                { "ja", "aad60aa301e0d943ad85023b18a3031ecb94973ead90ac49f2bc90cd23841fa3109b3a888ef6cb38aee1bedb8ba041023bc88ec6329427905a52cb038166d308" },
                { "ka", "3ebfb899ac9e9dbea554bcc964aea30f10d371ccba9265c199fe50037b311bf51e4db77877e4203f4dd2648a13080bb26b009516bd39b21e130d40017d3f51e8" },
                { "kab", "26ba1530d6e2c9f3c46513ddc611d34aafd9bfc3280d72031de01df7d220d063a6fd4f5084e852d56bb42a99ecabfe2e8a53bf54d6f9d0182a1ce587f2821267" },
                { "kk", "330bd9386fe64879e70709b5192f4a88546aaf62f22c05db1291fdfa613c4765968c7a28d7c000a9f0245fc43ab9ad33bbdc9f657346188f1acdbccdab4be6e6" },
                { "km", "dba3fa5a94b47064f5798a5ce1eea4fdc9efe640d7240462c639f1ed09d6fc7bb56ea4becde12f9d99bac34039ea5a55462bf21b1c2b75f07b77974395f870cc" },
                { "kn", "177a59b2a8124fe91e36c3e53953ce09c7391a7837abb3191ddfb69b3a563ac9e6986609790209070ffa70ec47e8600638989c0d8467360b427225f643251d2d" },
                { "ko", "024a56e3913796df717de9153a62a4aa105048459dfe42ea02595314d7bda2f887069886689138dffb7f8416c25e358063b1348212ef2fbe1567cbf65a9de3e3" },
                { "lij", "63ab4230b5e8fe9be3be9354629b499eaaa228fdddd616da913de68cc46f739314c350c46dac4bf7b153dd83d848f7ef2af2cf538788a11c32970d80c910c1d1" },
                { "lt", "6182389358b9af2b49f7d695d0aa4109a6d494a947c37123283f1320d6e55f3c06e038f3654f7ec30214960383353883b2c190a86f8ec96f320376c8e6fed479" },
                { "lv", "1057b8a72518bd923d07fe76a33824fbc9d0a139bcc04920553e271d333c9e6320fe277893220fe5251a1caba9b31218e994efe04fd69430103f6b9cd8111d24" },
                { "mk", "399778ed957178af73e08041cc98d21b31e2026b8cf7b401a97cbacb7c2d08196f10d1b1afc9930a1b6b01284c496519263f8d97f1148bbb440b97f30b8d08fa" },
                { "mr", "a5087f3aa1ad24506b7ba1f9b84d6eb9c9d06ca9c11761b0ee4301dbed75645ba7861340bf7335401247763472290d2426e4e4c44acfd2fc5ef1efbadca5a2ba" },
                { "ms", "074ed638063c69fd49038dce888186939fbebb0f0dc7c3566e910a5456eb6cf27506a97373db441e036cd83fc188311924f9c1b3587a358c8a547390127a1b36" },
                { "my", "26228c8d8a867a92d44da0f9e7b76fcd42f310b8981407314a531b26634f995198059b2bf458b7ef5c1d6c8775d89337d1c016bbc5568b21218b952d9a5389eb" },
                { "nb-NO", "140972f03c33efa59700dcde0f4cebd6061d87089715eab9ce053f6324c7d050614604261d6cd62a86277f1ea44e28bc7f0e5385a30efe22281cb79b0d1cd70c" },
                { "ne-NP", "74470c1c2fc7ae423ad93960379a6265678b10f07758b8d38d69cc4d81cea4812be6c7b6d7f4af304f1cffc554b3b75f1f91c6dde5351a1bcce3e22340d5387b" },
                { "nl", "b904efa6a6727d1d4ebad29d3ea3f68f8b2ecdc177a4668c189fd0956aa591b0b39eb82a0d8a19c2060c6a1edbad6891c3e1d67e9f46d2e22a30d1a933f2e469" },
                { "nn-NO", "ffcae17aa3f3d36cb54f15bc90a6274cfedd34eaf48c440aaa2489fe49fb9d16aa3dc1127f800f4f1279fab053d51f36f747345c15d7b60a8711052130f0f0c5" },
                { "oc", "15d6822b500fbb0340afb91f2b93129a3f5850d3a9c6327879dfe75680d14fab4b23dc43a40e3ba213b82608b637edd9b8db92e43b35557482e6aeedf448ca44" },
                { "pa-IN", "4d02288bbcacf9bf2cbccf48fae5964be1df28c837e153c0f3dae7ac3e6ae097bdd2931012311ea9184941bf53ec76afe5cd0371c075ab601f770963da75f244" },
                { "pl", "6d3cff3e8fd4ebba60d03e0703e32f4687ba526a5412479cf64f880e8c54cda7058d52712a5cf18ce0484d19a8dc8cffaf9519813e4dcc5f4ea22f7baa4eaa8c" },
                { "pt-BR", "e028a5d99f868bfde9a2ee7c077e8bc77877a8aa2d892bec398bcea915bc80d547a1b90af1f105254b8c44be9bb2ed959b370ca92922cd1eed7e6d63b553965b" },
                { "pt-PT", "3906c7278f2e110a1829f4520ed2227b83b89147f486b44e50ddbf830bad3ce643a905235cfb5535be06d14a217afb1c66d82b0a179839263b94f4feb1e6eabe" },
                { "rm", "dc958ea121d131a2ddf098dbb4b686758db65e67eef35c34125d96c4565063a2582677327ead89cdf42556392c7fc24c010b05cf678d56dd7707815151b57b6e" },
                { "ro", "f9dae3e2af83db7c982171bb880ae1f2acf36c3e844f9921924c4352f2f72a0a2978e82a570beeb394fb1ee0f5ed7ad6f112523b0cf5db3eb2f100222e29bb4f" },
                { "ru", "63c9beca05c425ae5990ba3f78db2ba1391366a89eb316b3dcc49e0332524c8eb260064450a1005bcb907b9216cdfe8b1fe1ddc26a9475b168a2366a4d7d897b" },
                { "sat", "847eda937366ad0c24ea0d70a67221e2af1e602b9ceb724083c3e0e52ee5bd31e80f21f73ce2c62393d5c20e603ed97c4a69e5c49cce02ea20803751ab085a43" },
                { "sc", "0d864581ddf33bdece4d44854eb4c65fb4e442c0845fb784e139c6caaa8015bf13cda40034ff62b1a97015e56fedeab6b38b9f557ccaa7c4733e2a97f9cb43b6" },
                { "sco", "a8bfd915bef40a1c3bd739b72fb1ba96136caabc7103992fe977ef32751dd7069831bcd644e036cbc3f8b406aabc9e638921816123d0f2c2f7dc30a5f0b49cc5" },
                { "si", "bf217abe1647ba4ad0c467ac825a4e05621a2ee3d89aeb8a7cb1e973c5d9688bd37a9010bb2b5c364e150320298a87114c4853d697f036727ed642910421ad79" },
                { "sk", "f9dea9241ef53dd1797a457eff8651acc7e384cff61c39682a04d4dbfc355365cfa505324960dbbf5943cf42c00f2345718f0f65ce2c85ff2f20e514a8307547" },
                { "skr", "550b6ac443ca3ae5c8984c5470d37ca5eb7562e15f28a1331133919084badfb71e2bd5dbc01c3671d1b5d49ab178263509d2f71b8846581da62c9c4ffde19f8a" },
                { "sl", "d18875a5c2ac873d84be585ac67b6038db3cb3de9fb4dfbc63b462c9aae9879b3f7006d93cda2d0e05642d074ff0050ba812870859a85cb641fc7402e51362c4" },
                { "son", "d559dc6db53e485d30d8110c6525ae7714d59ecd3e5a397750efb6e5ce6e60a1d5287190fe2a8b9749e54b497240d6528278f256b01cb58f3288e628b51ea87e" },
                { "sq", "1bb710aeebdfef822ff5aada6f70b3f065dc0aec2d1348149671b6356d0a1b651f23a26e835385b3830557a3caaef4ac4be546fdaa96c4e03fe05ba669c140d5" },
                { "sr", "c2539f1f576900064e888d3944aebcd3abd038fc37e01a093f4fb7fcd5f030bb51a99a8f5285f7a8e3507ac8659507b6914ea3dcb2176ce54f99dda1292283cd" },
                { "sv-SE", "8a88ee1137d5e26384df7bb5540b20261f6ca0de4da179663c566b436015ef6f88ec19a3c372d46cc9c122ab85d049cb08f166be3060b90126143da0991b57b3" },
                { "szl", "c178d39bd71b7762bb5ab12ea2bfa587380957fac9cb5d4819515b2e72e1b6643de65adffe6b3c5293c1f55ece86183a290f94a5036065bb2b6cd83a089eade4" },
                { "ta", "7262cb57d474a69c95f7f42e2699ce8731ca56907af2835ae8f165f87994dd89f4b9c3203983fc231db086a9c059176f121bef9030f63db810af8fe54c3a6899" },
                { "te", "b423187fe765688c22863820c74f7e119bef1488f7a7dfe4a51c8c21bf7a98b63707ca2bc7471dced1a5b3c23927b8f4ea3fdf48640365d749705b5e03c33ea5" },
                { "tg", "15206e5d8e4bda734807f511fd0f988b93c7318449d65c8cb584dbb41214dda1826bccff31dfbdca1edbfd4a68e97417c5a9299c412276a377d8c9eacc1e2f8f" },
                { "th", "e66efc3aa4ba62c681545050c01c63cffbccf01dcb10af3eb09f9750033d37c71a3b51483ca51bfeedb76e54e1ab830ef0a11552a20b327fe67e3f775d9f848b" },
                { "tl", "13dd1be714f0020ee420ac95ab0ba4e259a9bda1cd2d69649a19280b982e8ff1b26e56d8889609f5da5e81c14caa13bd3fae9a20cbf8f4370bd462017b46bf16" },
                { "tr", "925394d40c0f0aba05b2c035fdc0bfa7106d494fe1b0af06392b214aeaf28376d32b25daa22c9b29702a045b0319b499aa1b1094d4a8a38acf41afb021b1ff49" },
                { "trs", "761443fc7794b9399e4e8f6900b816c5ae1ba07354712ce22a3c2888f6b1804e18f4098c4d88c6d09f56cc37bdce6f9ac275a4f04ef7bbb502bdab94f1f5c8a5" },
                { "uk", "7a206d2a14803537878a65583b2b765854f3cb9716b2b998ecaa27162c09fc22b063e7b2cc5a7296185f5a24d1448ab6d9433d65ab60479bbef73904730664d9" },
                { "ur", "b8662bcd2e5fa5accb8c04eb7534d4dc2d0285db8da84058721715534740d45030b8d8037fce4e1f334e2bdc0d6a43fbea4dfb252d9da7aa3f11e0eeec1f6d15" },
                { "uz", "40575375cceed086fd53278bff2249d134580bfcf731f452b14a5669348986a6eed42ae1664f57f37fc368a48b320ac3a2a54e45dba14a44cc3172cda39d8c01" },
                { "vi", "c5a99ab813bb95b7d88bf811a2efd8a4f52ae02810c34bb009a0a5e833430bb6112fed4bc2a0f4946e3c5bb2b5961ebaa9e00ff41144e0f7b1297c600b486099" },
                { "xh", "8082c3295902cec4e70513e4dbaa33db2b567de06fe8af20a203a219e9527d11b8766bfbf4c1476d8ca2f008d54fede9397d725dd6e6294196bee7e5c4050e98" },
                { "zh-CN", "443e2635986d81067c32e98874248272ab3f8e341ca93f166937b8a28a634b46ab64a5ff3fb0abe301f20687f1469bf30771fc6debc0e98ae688b96d8fd328c8" },
                { "zh-TW", "32aeb8301b57f08000ceea2750b9564578e8fa80b345f5240e4882d186424d39a1567f6e2e8ffc41f0c781a4dba66fe3256f47d9ce71aeee2c716de7ac52935d" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/146.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "2ad82ebd17f6e83f45cfcf80d5da8e086e1bff93523e9e9786f8d7994be93f257c506be63d3f675cc9fec9ebfbed71061ff392004fe63f8ba868a235858a0ded" },
                { "af", "f294d1d31c57aa207cc248f066cca203df1547361b94afc12ba98d8214e38dff5323907f6da36677827a5f4843bc0cd657693ea127d1603746b3644382532235" },
                { "an", "d4724ab5136b506a6273beb003bf6b66b713778e2b677e3f878e0b3eb600a3696d0900aea51981fffd432d10600402f049cbb474578f61e31922654432b36505" },
                { "ar", "f4cb03656a1c88d2540d93bcdd685ff95e69492016e63f9f25b4f988bc204b12c747a34cae8f1c05f04b1351d7d0eace2fffff88bee7fbf6a4f779c171babd71" },
                { "ast", "6ee2120642d68bb378e0904606092d3c124f1addf43c7a2513613594abbae3cd71bb76c1b8dc1695cefb521913995bcbf4203c8108fa0eed25b78744d41c4c75" },
                { "az", "ba08bb69e641b7316502f9538ab989564e3aed9087402545546b28a2fd4a3d8c8b68c9139d74faf0d11d21dae52f16ba94ad5669b1d5e9447806fbcb3e4cddd4" },
                { "be", "1cc5cb06f609bf16a88618c54ac145a8bf75cebdb6210ed6aa2d0081a77cdd3c95e51eb3267bbbbab19a2d7fff0d54b14b5332b4bc78911986f4aeb66a3ab07f" },
                { "bg", "f1a27f98636b54fa8a105f15057501f3b8c65e4f2e8c55cb943250d9261bb7703df46abaff794974418bf401fc0db1e250aaad79a61051dd8433373ef96eb170" },
                { "bn", "b7513bcc77a2882a8d319a95463d34c676522fd22472c8261ddf732679349b0619e39943fe9bd6d7119d0ac3243a2215dc8bf56e2506af6f09b86c3ad0ef5173" },
                { "br", "87d2de8cd44d783d2f46c44c52773ebc1f88b2f6733955f892bed25582be3a0a3952f9b579c59092e84480d02a084b88469706ca8eccdc3c27c425fb9f6cbb29" },
                { "bs", "975fcba794c67d54d6f0b329555deccd9f0d9063b2718046bd9e4b45209541db628e61358f1454e8f51ac70d123059c2a1ce6ce38e760a0cfd19ad3433f17bdd" },
                { "ca", "17601b2801152fe5d3e8ae5dfa2c407cc97710cb970a144fe934e8bda456712f4e97df77629138d3f8d77e71b3a5e63e0b0a8cb1abe55121a964bbb8a369a823" },
                { "cak", "dadb05590995fb9df34c8c8a7d514d9c400d979d95e8d66f2ec90f1d796951abe8e7a842c35dbc50073e8d7a4d3bd02e673c3390d7c69e6adea8183e0f9d1e89" },
                { "cs", "19860268b2f88283cd6479ca4cd95a77bc61043fbd2bfdbaa2366e42e58420369eb94dcabeb4de87740d9228588f2b2314448c46400699f6a098c1d35ef09044" },
                { "cy", "ecb05b52abdca2acb5158230b35a68f360ef0399657ceaa6cd13296e14abddf5db230b3face0dafb86df02be597d588c5d2507abd1799e05f0afd7f80ee0b6d9" },
                { "da", "f5351231b59d10b640fa9ada13ea77ac9f498d08b1bd629875ff272920509f7ad24a0a3534fe2a0936f6e76c685114ed7325f4b82e17a5a1c7037c7991fd4cf9" },
                { "de", "7d51f6da6c84996c3bcbd4fe32eeaf6231c85609c31be190bf804448fd12909d6b7114f3d5e5f4a86206d5bb5a0ad20315a5be117efb57da22ce6d07778dd9ed" },
                { "dsb", "94ac0097432886a19d32796ce5ecd97039aed67d5fb92e447446e0a9b11a252c374cf96f30b6e3e276b08587cf3905bb23729c340ba9de06e4cfebcb6cc92759" },
                { "el", "0e4e961794faf8b27f9896d8877c3d54451bbbabba744f3b4afe35186ca4f564f6f05279479f86721489997099a88bf2b6c3a40ae7d2b8890778016b0a8629a3" },
                { "en-CA", "f74063a96625db71b794e92a7ac8e07fb5773e8c69fe3ef34df46394e0bc48a4014bff8aebf712bc01b2e85979d47f76f63d34b4a05b945560758cf3440de0d8" },
                { "en-GB", "48e0a21ad251544f2afbfb528f215eb73561c3144f5c672e9cb14d4ed9d6000a53ea1bc7d42684824be4fff6e7a6d4ca29c8a945c2b7f665e76698b80ea5098d" },
                { "en-US", "8f319aa83df712956fcfdb619295ac3ecb94b8d8fd96fb73f661818774a9340d113b1766e3b8f161837e70c6df4111972cc51c03f95452eb2f5350043020233e" },
                { "eo", "a0b380375f0457d0bfd7ac0855edefab1c99a99748697e7306682c3fdeafba7446487a4f1fef8e8754c97c402cefe6362e75991ff5b4c5c3831fe7eb6b303fe6" },
                { "es-AR", "9d0bb09c796f7cfb172e5a4c0f5cac7220065e8d6705811f319637bd5b1f30c1a1ba40ca51da1206c8518c0e79288036204bef66bf09e6adeb2d7294dd5cd683" },
                { "es-CL", "177c64dba54933e2256193e19b29632e41691ea33c93eeda59697fdef96a3976581c5959650454b8497615220abe9df8251d2fac233731ce103cec2b3153ae51" },
                { "es-ES", "35e2c483666bb4e326cd674eadeabe735515ba06528fb49dc52424140f68bce6764122902089ec14ef782a50d444ad3d1651e7a263e551da3b8fca0751d3ff2b" },
                { "es-MX", "2861c13ef7b8ea41354053218224c8bef5c7647a8116226a1bf9a3aadac0c2db4003a62d8cc13d39cdc5fb5cbccc901e7e3d9dfd2ef0990d6de4453a5f9187e9" },
                { "et", "0bd1a70a1a8db1ba37b12ca50431a061fad31a7f19d4caad8fc1fc88213fa920cee060c56d1c341f6194066b93efb59f55cd47f4ce58a427b5ac57567226aae9" },
                { "eu", "9de516dd484e6d844ba0d07fdfaf5eeafb67889fc2c249f2983dad6f221dc886f03690228135053be0a585679b75b5929bca40629d6086f7a528b15073d61c0c" },
                { "fa", "6eded8f4889a982a6f856b8cac2a3e1d9cd78a07432f47b3f5c1fd3db567b204011c8dcbb78c1cf8e1ae1ce01b96c68cf5643f09bb9eeb50ac01c576c0a65198" },
                { "ff", "eba4c82ae0c49ab32cf552ac3db47af27ac2d84c8c44d6d4564bf77e200c71181eb0b9a1f6b47c3c3514b00ff65ce75b13a4361b7e7630d20ea8efe2b3ed35e6" },
                { "fi", "3e48497df4c14f0298b8c41f3e9a46bf5cd1b8b909d26b02bc37c233f45c9fd29697d270d725366d76f709ac54e159c3bb22a145ec78835c270b016d3a6dae3d" },
                { "fr", "4b1e69a081170caba8f468fb8a97a0caedc787865007e071816b1959d5fb8e43cc623b870bba0ef699fa5bab0b925182f1480a103ea60288aba5a67149c20f31" },
                { "fur", "61530762f9704c4011744e66b9c19c640857134723d7218acfa5653ae12791b75133e4734ac9c5d73df769d1d13f8e8c23273d80200ccf1abb6076e327902086" },
                { "fy-NL", "170af4403c0735e4ead645758a653afba37c06487972a7949c6c995f30d34c3cd955075dc038c85013eda4e65895daabc32c4a26786e6aa9d90c6a1f0ad989e9" },
                { "ga-IE", "a8811d1aea6e5a0d4aa3c1be8aa95a2bd4a933f54d3249634c3358b79ba27c897584bea70cbaa93c1aa286a74afcdf3551279dab061c63b9748933109de5e448" },
                { "gd", "85b9d2140150f503170aed8c93d2c9f52b1fa224a563fb0bc1a7844fd3259379013af1d1c399f4debf6847d8b1523eb16907c62f122b9221d9f973e9356b4b35" },
                { "gl", "b5107bebc4738ca42a1f1c59a763f57de13c7e20a6312a3087c46e5e122b774b4d7a23d330cc17d4d396e3082df5136d46e8319e221660d788763c4dc85b4ade" },
                { "gn", "a07230bfe9686360fa2f1d147ff720e9de6159d354d9497c9751d82259f80505581ae572422280472d36603c012a367b978990caea4f1e5e1c0fd9a7634f1a74" },
                { "gu-IN", "4cd91887ccc662c1008cfff765fa9589b1f392c80e701ede649925cd5f85a7a12fb32d4222d144e6f873601eed08dfe48b0878bae05d40883cb76073881adc17" },
                { "he", "19e2ce72f59952be276fbe2a7955f08673ff631d9990f326bb9a8c3c6d803cdbb28d212afcb8412d2fb9d974d9c71b014f095530f0dc7be7523df8581c3ca08e" },
                { "hi-IN", "c8951ebb5bfbc5ca6bd63efe3681dd3a1a6b2e9e0f9e50c3364f63df77e184be33ee50d962c30b9d2e69157b603475c668fae6efd48ae837e11eebbb0b6f25c1" },
                { "hr", "21f6f8954fe44e392f529f46cace0a9f068289ef75f97c734d3419b0b3a47e430564e8b4a8f148e3418aeffe5e096a2171b7eaac2b2bec92f531b08880244e90" },
                { "hsb", "b6441a25a018510dc182f4d05f071e66ec450df1e49deb53d77f1e3e62f0d75c50e03b50f1fdc688468ed0c535f64ba911dd7723d6fb045fc495892580b7ea59" },
                { "hu", "ca20d4b0e0e58058808acb7fac1818ec11f19927024e46cb7d707a26f287b3967bab8b1dccd49e497e5c236bbb6882be1d9442c07ca79368d1cd5fe7de103e7e" },
                { "hy-AM", "e07b3e81d9a415e8962a371490c8057734e64927e1c0bc4d75d9fa3558ff8343096756bda0a863186b0a7dac43bec71788f99c05927f29a82a85d1a140503cbb" },
                { "ia", "2df728c93c198da2fa2d124cd6808535d1c50417d0fca9e34e48bd44365d1df0b330ebf71824a1569cf401d40dcd41b1f97cf759b382a610154d8d0f5d6026d2" },
                { "id", "bc17fb55ad9853e3612fd516fcae0275b36c460f7bc03fcb914a77be08ebae3662139cc26df95ebfbeff9b25679447c43cc22f9c1040e31c819e34e79cefe1ac" },
                { "is", "361e7eeeee36849f08f204d1997049dbc85d27b9e036cdfab363ccb43f626656704b714c23e02eda9c807f6c331cb3f38479c0a03f83e7feed604b6fc661148c" },
                { "it", "e506df8e1f8b6383c449f083d13afa7ee5bae3166bcd1ba402a38f4abc2d0c8e0f1e810bd814f0b64f7e9b631f0b32955e7d11c0a591af78c70a8a1b2afabb9e" },
                { "ja", "9fe729021209b86cee4313ca02cff8793f2fd4d04ac1b33eb976b6f00d6f9b74591ec59b4d82f2d242b86415152a1892354b9d1731d77729e0e75607a0b8e49b" },
                { "ka", "12b33b8855e4eddc62ef40c1df04e2bd4495cf9aecab37dcad4c45c640c24dcd1f6aa8e5133279bd9341357a025af7033d465848510c5480fef9b4b549228e16" },
                { "kab", "cde86f31b2377e72ad57e2230cf304166033737befb5d39deb11be23cb9e6bc5fd338ad8d2a04e878485fac0a4b37fce952fa8f8f6062c590ef4264b49a4dce1" },
                { "kk", "e8e532950ec88d0e451250b23fb1cab409aa4db59ac1298b29570d384a6022af186da7f4a4efef6805cab0a76e16fae73cb66971a7024d7342c78c07ac31919e" },
                { "km", "839093e70450178ccc4fef0eb33ea8bba0e87fc03ef0a2f440339982d6bfad81b48127486f5279d8152518c6c2effae631e4af6b96f4c6008a01a22b8038a314" },
                { "kn", "309765abdf8c02f00e965d2161b8feb282bc5ef5092a900fce3e787c374584ea334bd773fab1f29ffb129c0707ce12d12a6dc5cf04ae25f9f0bf086d6fe0a17a" },
                { "ko", "db26a1a259ff9521166fb5e1e7d8a5d4541a4f95314a1f20df97c0d7a40390be9cc6366671e3b8b92c993895e7046e32a812f89165d70e30dd77851814f5b945" },
                { "lij", "439cbbdf292f7118aac918aab936e00eb8c175457199bee94aa57bce1902cb07550b36e7d81b8313a2b8f2d2f284908fc9764681a2decd77d0603d94ddb48008" },
                { "lt", "0e034a1125174bcf1f36f14d8fb4d8c8d04ef1dd300eb9e1c601c99376119b740f9c927108caa199928b3c3a256b26053510e1f1d4b8facc19bdb0014ff61652" },
                { "lv", "de03af880bf80970ef2f889b44c80813fca403b1ab9f5c04852f6b3ef254fa8881084a73e0db4983829a9f208394035c62c5766189d4d9c63556f8609caba23c" },
                { "mk", "649406e4161593250b0dbbffc26920be4acca9d5d78377313ae2c9b33d2bb809ca7c16ac7f04ad9a2a5871346809085a3e53cbd119f81225586a847a28e89164" },
                { "mr", "f70d580166074f3c6eaf169f3a602339822f214940e485853bd43eb475251c931b3e07680ece81d86f1efd0f0b1b527f2ec9a8c54d571bf77165bf4998ef1fea" },
                { "ms", "09a6b77f9a246e7cd218b5e03eb2f88a3c63ebf8f91d6c0a9bdb08728431fb158471ec8cfbc61e40b21695b9e7c10120756ad5c01e7cb390f4c2155a6c1319d0" },
                { "my", "5cf92735c109881318341a0aa99fb1de650816d978dcfd750aa72b012b52389ec2e0e59b38bf74dcc47bc7ac83b7ace0afd2bcda137d89e8b2b0d0b6f0065678" },
                { "nb-NO", "b1b402badc4368245b2d1f85a661f6dbc66d887f91f8c008aba799b016f491d3aa563b7f3536faee1f29ab27bb4fb9206c77e38caeb77a6dedacce9adb87f88c" },
                { "ne-NP", "b9a317e9eb1cbf978e8e8f570c6ae241a4f1c8a399fa84c9371a4ee1a6a93b2fa473f34e0f4b3e26151e84d11b2ddbef114dd2acdc438ec36e120de578184f17" },
                { "nl", "366209dbd2dba8dc02cf257e45aa72ba10f4c557dbbeaf65746863e3375c6a2391625b612193c8e2e233db3c265ccb537d5f1d01df34c815aead7d7f6cb2c394" },
                { "nn-NO", "b65e9fb1f8e18b6225288a620fa2d99bbde6194c2a764812198b0bee22b98a097351f83b74f8ba563db27cd4bbf5b947d21228aebb4ae9f57a10e2e5fee2780e" },
                { "oc", "66dea28b9e4bf547de64e04c9a2e29f414fee4b0ff3a2c6db6d8e69cc41946d8e9282a2db6937d70948628262594a8d4d2ad90b7c5a80d12322da793841f03aa" },
                { "pa-IN", "1d73b5b19897f317073a4899071c638f3a6ad9bd3087bce09e6d1965b11ab27785e11b4f72f5aa2355c02cc21c3354efff42556b859eae46f3dd3313eab53681" },
                { "pl", "402becfc59c5e92a7b077d06e23c429e896f20798474847398867738654ab44b0fef9d56493aa970866676a7cc50ef1be7d0e2a83a4da063986835c5aa71f401" },
                { "pt-BR", "408368d1367e9f4180eaae2d5bb195d97fa3c5c6aabfb2608c8df9c5bf9afc641614b59cd304a9073e45139a3d6cff69aa69aaa85c024be1d863253fccf89078" },
                { "pt-PT", "f8c4b441b3613d668dfff618b158bf36cf0ec8a460c02f2cb8ff68fe687ac1806cdc7750a97977e3691f75e01a2f62332e49e1afe96047c7edd0a2e8afe36850" },
                { "rm", "887c875e4989e6be4af4cbd37007dfc86aca7a2a7f584fca766ebcb058e4431ec34f72cae50e6653f243db12cd7d886a57f7ba775abf6639fcab8f58986a9241" },
                { "ro", "5dda1537cbeb1df493f20e6b2ffd55545edf96e6cfd65908fc6c3b28d0b512c2c2aac4c7f6c37ab241d0bfa20ede1e1af5c451551306e7c807889ec14d743e29" },
                { "ru", "be5d3de4ee856680bc82df81ab9da2ef5c353d4d967ce6b70a7c96e186ebcf3f7bdef8e2b4ad29d2ec01b4b98e5825946c2cf9b728090b1ab015e95a2708474e" },
                { "sat", "bffcf41a5dc0b8de64a8faff96f748409a806561757d37918c83cf574976c246ed5efa0228f4be13f4dafc7d0dc3a17bee4d4f587bd20aef4a98fffec744ed88" },
                { "sc", "60a37e7c3a3eefd2df8a1137061fa5286fb3e8ae67d674cf7a80d7ad127a6f6025d0a517b335ae1ffc075a0a9d3c955c84f417b4d40c5d2439f9a1f8e072fa4f" },
                { "sco", "f8182626fb486308073f57e9613bd162dbd78ec0178885d5cf577112af47aa9490da40576b66676e46022cfb4db04a8a43d35370ee1f8117eefc2a0f202ad2ca" },
                { "si", "fe124da9ca0b03f0e29b748a8cc3262e007e9b9d93a0dcf651a61ac50b09fa73252b4f8b343bfb21fc19e3e4f5cddf72f56ac87ee4df5c41b0c4c6dc20da190f" },
                { "sk", "d400b88b19dd38ebc500596fbfd6328deef39be59ebaf885fe04ece66a71dd5a7cb8bbade083079bec3b741fe339c89af7b6181830e7cd88ea144412f080d415" },
                { "skr", "c867cfcf3dee8e1c710e0426792fb82c575d7dfc7417b5273d60758baf52961395caf0339850a1984e54b889ddc457fa5cc7d21d0c90f54fdce79f34ba803610" },
                { "sl", "5b3318656287780d916ea9c563c3dd6b70d9bb043c424c49eaab4dadf394db9845bb6f91581594e59bd14377797a0cb5b33efefec7471b7554402216240d1971" },
                { "son", "5b66e7104dff111695d9b239d192151f7540ccc77682b6b69bcef6e3a95d36ecc797bd40031ae9cf652cd5fb6df018163f8d04f8292dd39d1ae6d450eeaab173" },
                { "sq", "f2eaebe532b02f8dde78e7f2fc954b1c581c8b63ab579b4a3f1112e57272d610ae0d0a26108e7c4f03672a311f27d5a90010aa672c4e8e66c005e062a216ba8a" },
                { "sr", "3c0101c735a104a5ad000803ac93436a157aff07beff36f3f236e4f22748bbf242c1a6b1ac50685edb9eca1ef850094b0e8262876c06d1c8e403b33afb225306" },
                { "sv-SE", "72b5de114f040e97d0a5605f74c13101e119a02551613f9e508f5a82464e72f4f1f846063baf81665a5af2c2d19c148fb2ff1dfc43595779bb35995fff61adad" },
                { "szl", "d84a53618344b7576976e4eb22dd2952b96f863cf1d1ca5165c25d1e8c253a924b994174a1db9975f3741a7fa68740c543ea6247eac2b5cc0e6aeb6773ca5a7e" },
                { "ta", "139c265311831853ab5b7db4bd193ce94a4cc5a4374b92a1068798f9af6a6e18a90bc715b9898635adf61b07894bd8a8256afa1479f41b62a1efeddedaca01b9" },
                { "te", "c94f0727a4886eb8b74fff7093814f5cd8fd3679a6b90b231d24b587d13c6ed56ede829deefe343966cac090d183962ca0a1551101e06c81e2ba3104db924d79" },
                { "tg", "2e7fdc1d0836847919d92cf3dacc7c458c5c6c7af144de205c66c12a2972a821c18ae074599f5548f95fb27a444ebd198781c1046a2b148303546e91aa1c14d1" },
                { "th", "ab8c7bfd8032fd81c20260f90db82c810940e631d7d9702bf325f4be281fc3e7eccd4c2ae6fbbf28a5a4e443d84c6a455b04667311bacb3c3c3936a1a877a643" },
                { "tl", "616b4c71fda3f729693f1735861c9252bdf8b796d88d5a0c211e1ec983bca1a71d51a6adc449d3ca5dba0b3a3ba1773e1978c0fe0513d263b748ad04dbf0db27" },
                { "tr", "04b1beec9f7f1daccd9e2d67488ecbfd7679aa39b837baf220b818b3b2d7e5450552c05a0c355bc548b7dfe20f00b3b96a7ee292240f30a993583d8cc2b6bbf0" },
                { "trs", "e94dd817c08b68b2bcb07b81b38cc0093c4fd66b86b89de992c913ecadb30c8a6e0bf1d47d60fbd524a40c9fe39a8e58b07975446ce84d931a1751f37efcf398" },
                { "uk", "1ab715cb6c876942fb4b3a8ca5aca44dc05e1cd2eecf59785601a7eb71e874d9e235262c4bf7f92865ce83597341881472c7c7ac45e1b3c5e54b7f5dda573ced" },
                { "ur", "63f94fada965f5a2641ea1be01bb669ea98ecb565917a5efdfcaee42caefa4cefd58d342eed1c5e7cb809988999aef598cd5b8f6283c8813ea382f467275c0fa" },
                { "uz", "207b903dd1dfca16f988ddb36665861e46f08e4a8f62cc1741b7fd93ad2291a92d4fd7fec6eb708a579d3f90fc6a04c70b77264721f314b413cdbd0bf4e3b389" },
                { "vi", "f1a46359320c628c9294f2d62fc76033e8b2a6cc8e56f8f9991621aa6463ed6741684e6b04c5911657afde30079c42f0b18d24dfd4dccc18db8704b4e6505b26" },
                { "xh", "7f094f522a6a5976e288637ec9fa310c1ff62c93e8af756e800f95c759f231ffedcbb6f2ecfb3595c5870bbfee26c799b8a71ac20b782bee442c6f68c82b0130" },
                { "zh-CN", "e2413c3d11099841e26b02f5e38f7bda7b3ae92af23b33252e258c224bf8ecb146f947b7aa6be9fea7cc234a50ffe26470fee46ee668597809ced869ab4addbb" },
                { "zh-TW", "c6c76b584d67ab84a08d98ce7d154b0f5b0a74fb9db7f748ad4f2857a803eb13deb2986268e62b227118621a853994dece7fcc8ce4ba94dfe29d73179449db58" }
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
