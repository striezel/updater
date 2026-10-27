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
            // https://ftp.mozilla.org/pub/firefox/releases/159.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "f699ce4eb7d734c855636894e65f76d45c2e7688e9f9bca1af72d74ff68d1090485c6790451f0452396dd8f1ee0a655b23e19468eb5bd57f4249a9875206dfd5" },
                { "af", "2f9e4579fa3373c98aa1611a1ce23476d5607f9dc18df38c968a64a4fd695141b84cababe99f19ba919b525a856fc9963e837d0c36f0fb2d04e2f1813d603fac" },
                { "an", "7289d6d4a2dae67404fe41d116525dff6c26f80faf6caa919b1f3fe6717c726e90fa9a228a9924e7026bcc10e45c666a5d10248b480227eda9946b5d52cdfb1a" },
                { "ar", "169d13273c24d25d24ac2d8f95ef752ee4876139fc1d958c9c64ae0409b9b76ecc2902b59575b5cd878a051536753e1930b7e9a17088b0768d48a1a1e3292cf5" },
                { "ast", "867829220f79c7a2f17ae830ef5f56ca5fb5963a279d16522f3c681bcd21cce4d1e4bc93748a1765494097b2d6d7a7a88e6175c500afaef2e3f3db1f1393122b" },
                { "az", "dd531377d89529bed0d653d27f31aaf94eea563e9f2da32be17fcf8fa467b71bd232418ac91ae932bfb6a7b57587f37be338e9c860f7e973c965a6f61c4b8f76" },
                { "be", "d6507bcfc94421507e1acf49218edceacd2f41dd1f45cfa77936da58db8b289c2b9376603d66536f56367ebd08f1f513481faf4e1c7cff455a053b55d3a9fb6d" },
                { "bg", "ef9ad52be11dc54971d7e16cf6ed959f72e6ebb7657e3668427dc80eb776464b3ee7d1555f3bff7084cc5b2f7290d1a5e4aca3b8cd5d65a3d53c3f596b794b76" },
                { "bn", "7a1a83daee45cd900cbcf5a3ec2a18b9ad541b15a9671e301c2dd6a9405755d1f7650789f10537c9a751fbfa23926d7d64b76b6fdc89c5ca29c4ec455cfa5114" },
                { "br", "3f3edaae3494c0c57f330bdb0ef9af2eab0391d72c3f82b4ca1c57084dcfa6263b8e48115c45d1c6040e4cb3d326c4e6dc3bfbff2f73fdab1bfcb6e5fa9fd56e" },
                { "bs", "8e4713deb87c9554e8ce19a2ce17dd4b16ce9aeb7acb8fa207b9303a2dc64e819da89c4bdcf47c53274df7b2a2883cb20940ae3bd28a5c4ff332632f775ddbe7" },
                { "ca", "9bfa9e53bd346c042ecaec20a86c882d3f04e316ff37b4a2c88468c85fa8047f1e6ffdc8cc4cffff576370ec128241604ccc04af7f2323e52b3d596b9c06a895" },
                { "cak", "64fb6a85615a59fbc1e5e28b6db030837dad481fd73d149bd94475ad6a38315a9b221b57861bea819a861141a10b770dd56b67439254d03004e6ee298089762c" },
                { "cs", "d910fe6c6108121e9495cefe1e2fbe7a6dd65e5631378bd2a614f0fa220b21c37145fba76a59b0ee54796d0bc50bc3e06706f408e7bb37bd4d4b8cc26e22c66d" },
                { "cy", "c6527315d0010f6ae44d7f5075d503b7b98bc9af1c64ffc67d014b4e13d28cf93affc593878ceaa1bcd708a497fcb023d3ce65d200208c718d1537621a5b18bf" },
                { "da", "f452bc2dd9a42d3dfe22f7816e44b6a5fddcd9a15f27bd5682baa98873d47df8de38d11761b4646b760f18e4f5c8032e0724c78b330c2cec9eb05f5acce0d359" },
                { "de", "5644dd8c47e26b5628e7a283695bc45be87cb316170024843f1ffad903f7824d48f8048c847bdb70648f47eb9ccf388e94e15a82e123332637121933b24c0dfc" },
                { "dsb", "42dc21cfa1cff8e4100dc1b6f9ab5e482eefe4de55230f597133385bbb6daa47035f640c4389925d7f016ccdda33cf15d866bc79ea748849e0b515273046b6ff" },
                { "el", "dc2ce7183126666026396fda8a3486834260c86ef85c959906724da795d66c2935f90a3e07fac5b445d7e429d12848cddd2ae05edb6f5232ca12b8f72b0ab5db" },
                { "en-CA", "ebecaacd2e535251f428605099e620f6561536cf6b4c5d19a0298e658f4bc9476d1a155a763024d99fbe7ffc129328e566ed17d2030ff055c020dc2a7a5755ae" },
                { "en-GB", "60ba1bd52a11e425019384e17323ea1cc76e80b5a9a98d17a5b73799c3c8ef5e4277197c62745b9bd6f8b52ed17f0d66dfa19c19db7e8cd169e0b3855b279b9c" },
                { "en-US", "73a3b6c5e1ace4a18efdeebded304a2f7fcd8d5695f61ffb399cd274b09f20226a1b633daa20d91a0b032ea73c945cd73f6feb5fbe84c6d5102eef93a11c2499" },
                { "eo", "dc6364dda35a8f663f93557f87957173564a0a1f7b32474c290340e4c50fabbabd1a49be9b162dea2ac471d62d214af7619996fa7930857d05afb475822c6f1e" },
                { "es-AR", "fb0eab9c634d8e1661e446439b8fdf7eebcef03b107de0665cc119ae2702068ff52c8474fde9092bde9e56ededbc23e8b7e2bb177ac9a08cbab9b1b5080a0dd2" },
                { "es-CL", "62ee30f340a8b1943b63b4b48f778db7894d8a5e0535abe43b2cb3a0393f7a4d8440914373f7acc4476e0155a1c4fef077ea27eb0a89a64c0eb01ce97c33978b" },
                { "es-ES", "1f23c670bf25c5966c3e4e310fbd6494d22fe515e2684ea607fac77c35e52c5dcbc8ad086a0ba2c4d2fad1e3ec8bf9f5e37c7f39776ab0381564e6b1eff7dd1d" },
                { "es-MX", "7662a6d6b6915adf3e31c21313b1c13dba018977c020bbee90b5009799dd85d27aa8a7bf5f5ed126f6edd33098740f4465975580b9ed682919c0f7456f04e173" },
                { "et", "7a469c1e797b3f99ef8480cf69fe8778ebc0aa2ff26121462127a436330a675b34b693e6d4750e063c9dfe293effefbaca4f6e4776f5c28e54cb31e056f71510" },
                { "eu", "f0631179f21a6cf6669facd556521026b17d31ab456462b8d465f219520c228326b4e10292081cbb5bb88b0b893bf3a1d26c1bd289c06607c1fd92dc581289e0" },
                { "fa", "c67897c84b888c77f655f6b57baf76140bbfca969b6ba1e0e8292f1a6b0534e5fd3b9be6fea05f70f402eeaa70a8bb0557102bb65c0ee5ebb77886ffefed3e34" },
                { "ff", "2e71d5a08cf665e7f752e23ab47fdd31457b075a7a7976aef5822f232d5ddb73cb9a1aa404f5148af0305f09dad461e1c70333ef327ae1ca7a5a858331cad464" },
                { "fi", "485696efc1aca5d4b68f4ac8d22e65f7af6e82f326818e6d323647a46d53f5bac9051a7c81a2d092592297465e53a6b3ab76c1ff84b4292877d1ceaa325e3766" },
                { "fr", "63d8ce4175313b2a1f113b06e78a6e900e85f004f6004f3204c8636c77215b2e73da1eebfab1e683b7ddfad279817c5c53406513b6391fb2d7ffcb8d9c960c57" },
                { "fur", "e6ee362ad76863ad94e55d208d07160b53add5c8bb6eb527d484091e3620e428acb3fa2acd0f7e9052f2832cb7d46234906ae38132f34e7f0e6f0699a5d5a5ab" },
                { "fy-NL", "1dc481b3a85d7ec90b3f8311689ac6778db398fcf07bf8695bfb99484743175730824108012f30f7b58dfc41ad29aa198ec06c62c569aaa4951fe342f8b5bb40" },
                { "ga-IE", "23a834bdfdeda8cfd3eb07c9ca0802803104ebb4f9e822b7227adb486b04e0a45209db5bdfac73211c8544b6caebeae64bc2e3ac18a1e03378b4855ea9fb53f5" },
                { "gd", "db27d6bd59ed9070080a6c04f622ee571ff33ae0537eedb9a41f43faaee9ff519b491d9b49e25a7f34941bf27b637f61318362c3d47804c4bb1df32de0096c38" },
                { "gl", "de5b5b4f701ac2debab3d59a4366ccd38e2435a23d67d63fd04f246bdf981c55868edd9f06a6df3055f89e3b327b42b4613d4ba39fb0e81e61a065ca805eca05" },
                { "gn", "ae8a6802b221e261d1372e7db9cf50a81fccef0d57a7bb63a4ae6eab8ca2f663917b5c7db9ed9e36201206e1b1ff631d8d047c14ded1e1c1536d6180b23ce704" },
                { "gu-IN", "c6d4241388b542e0a93f93533a8b6aa069247c3cebd6b966007d5127918e1a276afe6320537498ebe7580073a4dde76093fb2e367034913aaf188f3292480211" },
                { "he", "7843b8fd1d29acc4c28fe873b7c8c121a6cdde75bbb8f6f4f51741ba9d77056ffbfb63427af933f4805852f6380b1ed8e96160b0e7a63ae2478047fdd19f3910" },
                { "hi-IN", "0138a8d73c783d612f114a2fbcb5d82c1506085f6463d2d0cf0ab479dd43031e68c7dd4d0c5e11b39b7d7a811d4243abf5d6412d69933bbf85a4d1886f860a3b" },
                { "hr", "aac9e15b5dd00b4cf3b16b9a8e2c3d89618f222c14c53118cf68ec2190db6f4c6e26c029b4b06794d2f3962def106b70c6b4c8f1aca4adfff3a06aef7031260b" },
                { "hsb", "21869f5d2f880e71f2d2a85982dc3091adf7e6d6e8a14ef6dad39fefa431276505bdb8132bb396ce668b9a3ae6876dda5f6d69a30d2e82e0fe6deecedc8eb4e9" },
                { "hu", "e7700f07d4e2b33a241c809bc918b98b0348321af19c0ea73095ef629f1d43a72bd8e1fdd03c26721cc5ef001c748fb6a18453636a39b23d7da3d71285c9736a" },
                { "hy-AM", "3a6d7d3163e38b0393104f79c22a499672fa975960df2a6ca074fd112d0ea7cbf56aca5abae118ef012be004d61133e0c5f28b405b40c500cc012e29cfd92bbc" },
                { "ia", "c897ec91fbe753a85ef1b52e6b8bfb81c18f43a52e01750e8a34c3f7bef85fbc9443c20f9a5ce4dbcb0a77e6bc7f041d23f2213882554500e580e4e88a1f9387" },
                { "id", "92782a2e929bd44cf1a0b46f1f5de7853d251f0a78d0a6b58d792e9cad90b61823d39e911a883cd4046b9c4759d83404a300f21afa83374e877dda3a84aa49a5" },
                { "is", "0c947cd9a74ae2fc746b790c07c0854f2ba2462373f4cb6071930d011564edbbf9b3cf101bd7c07aa2a3859838977939ea1f318460260fd07be1992347d67655" },
                { "it", "1a86a217618989968518aeb028e884b158b9fdc669732b4675104128b65435be5a48530aedb14c6af4e6af7ce09aa57b204361e60557390de74e6456fbc008c2" },
                { "ja", "b960aec4d238ab2aceeb47251ad84ec461ec90057781ec38b56f9d8549f0fe7c6d487228c33d4ff516a997c745889e95848ad8c0c7b741e55cf3de53cc86a580" },
                { "ka", "52e10b6777dc34fa50a3ad78c26efb936fb849f137b71531f922de537e0608879c54f850318f5802115d9052769b848948ac8031d82bc31e7ecf53fb2f41c2b3" },
                { "kab", "c6bb86baa7dc4f3cac9887a5c1f3bf9bd13fb77631b5c94bef68b446661944af77a120ed12398df7494e7aec82cad60ab117895f4ea0e1ad92aacfa4a65baaae" },
                { "kk", "3dc0ec7d77d90e4bed292d580c834e15824409d836d773424c4042bf592051f7f630d297517c4982b299414fd9ad3317abaa505bd7fb06a148cd5493026cfd3b" },
                { "km", "5be0eea333808536a338c9d98f9a88e9adc91ea605180f80104393d6e7993cccc0a6de06255274e0eaf13a4cbdee24c859963d00cadf006703518fa58780a436" },
                { "kn", "eaef8f53c60475eac9ea2673ca3cc684a9f0df30de11637b0cea7255ed4e0257473af95d51c2b63f7e56e01eb0a91f1736ff99094f4e8ecf8ec1fd738dbc5bab" },
                { "ko", "2e073c3d8cfd91039180b5c7cb661ae50c56d7eb7644bdb3e785aafd78d558a8f5d1689ccd96abd913bebe88a38b988d9b778cecfe1bb6e1e2008fe09a2155c4" },
                { "lij", "4808a8cbf84fc5970bbfd5e6dfbcaa3c3fdd9d6fa2e7cd2ef9f46276a6fd66bb8e745c30f30f1795c182e37bb510856a0b249f6d4eaf561ea9988034b034bfc6" },
                { "lt", "786957f6f802da3c5d2033918106395db0626ea6a79f89a60ae97affaac4353bb0b40994ecbcad4eb9db9ce07e5709e4d3968f2ad119986b89c1f839b0d28b81" },
                { "lv", "84c0477f7ea96e6e8cbaa06471c28ca40a66cc4866153723e2a2886b671314e066be09eae89ba6e8314094f1ad831245ce429a0225c7b6b18e84778d69d8f781" },
                { "mk", "69b0fb5c2333340e318c106bf6018c6b55ed16d111dd8578d02e1fd150db0f98e2da524614757ba56dffa884a5cfacc48dfa8297e256678d52f682f7124b2982" },
                { "mr", "fba11b970aeef9bcd26fd3e12a92ee7e080c7622b957cf05582548ff9ff7be507c0af263c181c03b617849782e6b253b9b09070df8693b421a51bdd55c3b8211" },
                { "ms", "df38fd1b7152063e6e28d19018a61ffe0354a80bfd38d8ee80df516f91b8d381ecb292e0755903bd398ffb28e11b3af6e26e124167de0115950e2caee331916b" },
                { "my", "be448d9afca7d204017ab9743a3c91efd6c5d30f18c5ece98c0ab345f7ba66d9135c1ccdebb70b5558886f3a693dfed1062bb2f2d78418b196a54c3069e75a33" },
                { "nb-NO", "b5f2c922313d21dc34c2a3896d42d5e34f596b6150f2e74d54e77d84b852bed17cf1c82f9b50565cd8d6b6fcbc6a9df479a21710021a58519b1582cc7eedc043" },
                { "ne-NP", "7210773187b40d480be43d9205f101fb758d52ac1e040f0d58b9fa625c3a60a0d57bb442fc6633968bfbcb1fa68cd159f2ef64305c5bd344325a3a4923a473f0" },
                { "nl", "76a70248ba8aff00d40fa85a7e46fbca3d5121620f31da992b8d8ee4646596862e74d7ffcc6f46c2adbf69b1e7505aaddd9c2ba24f33968cd30ba749e4e3d2a1" },
                { "nn-NO", "70d69562c90ca587080e7f98e46a65e60c39ed0fc2c758b39175a474609f2961089414b04f75e85570a7211951a9c387939bc9d7a45ff840fe381ff908bc6118" },
                { "oc", "03ff678c485fa10a151779ffd2dc808e0379945fc7d0a384ee2de042d3617cf192393d2c79851fc09a3ab4ecf1b66bd0dce670656086eccacb317349b86e65d0" },
                { "pa-IN", "6b6cfde18414c0e3c6dea4b29eb5ce13bf99b4b84538d3b1f3217f3afe07bcc15cdd08d9c1070bc3990dc72bc2c8d000ffc0ba8b5ebebac8ae412274040cf2dc" },
                { "pl", "c33523f7278c3025fcdc46fc92eac5914023cf5d9598f4331e142b6a911cb463c2006e7961ac93c41ba4ed53611b751e5f93d28a348bf6e8bad8d546f15f12cf" },
                { "pt-BR", "0a7c70cf6b8579f39781d67f9ca17e550bd6f6b6c36f4ac86cc7fb5339287c2513fb4b691a8fbb3a27cc59f09272100100a7119d3ba07543afdbcc4e06a24d2f" },
                { "pt-PT", "d53e1c15ba05c63d5e0fc2454e1b97ae45ac69476e050a1d1c8663fa2b4185e19b33829ffca1d0fbde3f7273ca1aea4398d277fb0c30b1f760fbf775f60fa73a" },
                { "rm", "11ca15edf932a01536c655c369e9c2468413a01d3f99f83face0add4d666ecfc44b4066844db8232260efc98c627c10f1da5ed43d9dee9109a3c68e96c4221b3" },
                { "ro", "07c9d5b2680abd7ce1ac4b1184f8428470383a8cbece680f959219a17db0e8ea7f608d05208a3073907fb5fc6ffd14c502f989a42d07d6e9040de2d49cabee35" },
                { "ru", "24da9e8e8002960acd6b2c9ef7e7a03aa434035822e7c898fafcc9543030f8a2abb42177eefe8b218a851167c9b6731dc2c6661e03de7bed8b47e6034b02464a" },
                { "sat", "47f0e6178c29e531cfb3e312e9e02729cddb6b7500f5fb5e90c642d58ca9be85fc8f0ba2beb6142f50180f13e7d81fc497d132f4c7afc14fcd30b57c971f5ff9" },
                { "sc", "5eabd92b177f369759e1f35e8b7738c13e418468915b6bb0c67b699d19d26ad7ed0e0fae5ea25150c41f04bbdfe2421847f6f2609adfb133c77dd651ce46810b" },
                { "sco", "fb427a3a6e373ec2e506ccb4fcfb1befc890ab6b50abbb08f9e972efe29be31009787f6c612a888863b87deb8089549a52a701f94a94aec7dc5847ccb71efbe1" },
                { "si", "439fca2ea7aa37eabdf48c7824d21157cabc118c672203e4e421749e919ad67e305c30d804962e6b9968a8f1b8b2db358899b4a487e08467462d223f36e13e19" },
                { "sk", "f2a156f453498bdae8a0f430982d44713512e899ff18ce9fa9cc6d6b19045a93d3e014d95f2b274a41962fe0753b723607095965acd98e71bd927ab297ace58a" },
                { "skr", "c28a819963efa45ace5e314d1c535071ef332863614b3cbf159d97df25356bd7611c5b2dbfb63ab4ff34405022d8759225c6e41e5ec6c8a3a551006cb390b446" },
                { "sl", "4cb394eb283f2ae33302f85532299f4b117f2203cd7593568741e9bacf02af50017ad8f0c96ab298c974766eb88e670fa477a970351972be0ea49007545a964e" },
                { "son", "0434df1c8b8a30bd93410fb763b64fb7ecef9d94e1e23bed85defe22b19d59813bf3d4b9552c27cf49f4913aaf101c4b2ce701d6876b09f5bcfac71c6b6e8b02" },
                { "sq", "21c4cfcfc1c099805b1400d0c49849345285c4b8d571636682ed4c8af4492c9e6ddc9b17ff1bcda4e4f8e9b405641036e49884885dc04cd99b89343b0d9251bf" },
                { "sr", "77284501d77ec5a90e3515e110f320e59c6a20ad31f4169732532da3617b62374b5a3ea6ab9c8d84c25daa8514ecd0961f19992fb103c36badc68404a9d7eb11" },
                { "sv-SE", "cc4bc8e70de0b84beea5a92028dfbfac8abda2779d02bc6badb0624f95efcfdd681548a2ca0a27627d3c193ffc94d41a1aafcd7ab354e4073a6f2b7fdbf1db32" },
                { "szl", "947a462c6c6c3528f0c93f19dc084d26524246b8b7e0909b98de942ab3c92609515db2b329a4af6d93b5c6188a5f9e7d8743f55b5351307ce854f37d9b7150d2" },
                { "ta", "1ccc9465587a2c80d91d5acd35f72c703f9d7a1b32d2d63673ddc0603bff29fbdcdf9e7b46de92f67c5f676017eeb2daaea7ac145cdf151897aab1f60fae2c0f" },
                { "te", "e34f471cb792f5e4bb76ff8cac2cc8f7a684b192d93e55e605be92bf910387a7ce8be940d22151d659e95fac64c4e298e60f438e21630f5b43b39d18f8e9f92c" },
                { "tg", "71c802ae01183178f393aeb2407f700feb872e512f0eaaecc98735fd98c5404b580c0b56503fb7d896042ce3d168232f667cdd065a54ae2caff5b27c2ee80587" },
                { "th", "523284b0731d54d7d4f736713a984375c78fc0107801d70dbc6beacb2016cdb3c5ae10e762b0902cf62d5b061aea814fd20b303ce0a572f7797d679af6676622" },
                { "tl", "6143460f0fb06b55b0e6fba8ab28f24c082bff73c98c6edcb83773daeca026fca84a06fe169fcef17ac0973406a509d93fc99dbb5ba5da4ef603d956021532b6" },
                { "tr", "c487ff79f7c5e767ab083bc1da6a0669b010d81ed0769c823729157a077c74825ca0b481331542c534fbd2694f0f8055a3cfff94a3d00d19b80bcc198a7d8da0" },
                { "trs", "6990a5050001c8657897dad54b8f34edfcc99e3636ae00cae6428169b9f599d857db34b54ffe723b2ef17e33dc67635b845df47ee3d69b3374978cc916287221" },
                { "uk", "1df3fe5628701e3ed5cccbbaafd6f16b1e85f0e99f5b0626865c4be9ad7ad7c8864caba694c3244bdbc915d5ddfb3678d3f68aeb44ee2879f8bc50d8db057933" },
                { "ur", "d6a9bbbaf3fe388f51a135dfd87a76928c1085b593b4cd61bf6ff7973bc60cf777368f0e94c21c806e71e463249f188fb5f1e03d6a5053715e5ba10ca81f0274" },
                { "uz", "62ebb84fa039aefc3f0e3dc4c2c41b4bfbb00967882c65e0b425e0f18bcc7132989b4733aab1b935bd5f9936daf8cfa2fa9fc594389f4eccf4e748aaa1c41b95" },
                { "vi", "b4019106ab9ae875ca0242ed13607ac1774bc1614937ff3faf9d763a112f930bd51dc25a074e623e9a3392a416df842356a5cec0ea7f186b19e41d3d68413828" },
                { "xh", "b2ed9c7fe5ef4cea276a2faf002a262370f58c6dbb84d9bf8a0d62e3e0ee12856c75f30a499ac06bdcadc37e0603f1a8033fe92faa694e9c891eef4dc4eb792a" },
                { "zh-CN", "324fb701335993e1a41cd9318d82b68ce16009413e03fad3b4b96270ece0540be5cdfd3eefc56c8f504bd369d19f4ec027c0efed0866df27e73d9bb6fc1bfad7" },
                { "zh-TW", "ce77936da39f7b5ad8dcf49b8a38580883a621c40cb5c900e92ade346ab32cf1e614825c3cf9becf79d62f835eb475b32c024f9b8383f30206b8bfca7888ae63" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/159.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "d37dab8b7bc21f5232e77250a30dadbb3712e4f2735c7e0b636590cb10ff83e3585c729dd49c63cc2a4113bc467ea0d7d88c254ddb11f31c471b3c57e014be42" },
                { "af", "534ef13712c5c51d1611941fa5def55877b2ced8d1898a8cbb70cc509261ad7d1f38c3b855cace936e14b63254c46bb259cd7434f73788663879f0b539dc6c65" },
                { "an", "a1b27037b6f4d31e9c2a74fddf1e807d2b56748b4928056f17c58255d61e48841e36a9a83a816c77f87068099fe20a86c1348b4f723558734b0f1ba34f81d8b5" },
                { "ar", "20fedc92da27ebe100b818fedb2474879e7b758a297958054251ef372198497a9854dd054c94c0d7555ca3a738eec004b046813b633bfafc8e0d292415aa3bab" },
                { "ast", "d14df1893722e6050483008b31a19b09002e4c680a16fdbd2b5beb6711a7a83630837513090169b01f90d4ce4b3f6ca6a4e43c926103b841e3d6a12e4cd76a82" },
                { "az", "7f1714e393a282b279dc46ec021b7b2f049f88a4ec450c1b11b6038e23529a6a46ccec7b7a00e093790a41448e5864785680f56bed4e28bb3e0cb37b119b5236" },
                { "be", "16e4318265b270ff81f9b0832fead5448782817b9e959aecc38356aafc2e6d68cbc78d2d9bd218b94725853c2e170c3f06f7de09abb23584b942455e17e8712d" },
                { "bg", "8310e0b9c972670913ebc590f380bf427bebba74ba77ec7a0661cdca686b8e3b3f6c54774fdbb12daadbb165847bfc68f4ef8307defdcdac81061961133a9e71" },
                { "bn", "3cd6b3775856a8bb77fa01fa48d22aaa5590068ebc2c13f2c44d7ade4e41859aa0dd9c20f32f5602f5d6fc147d6a2c4947904a2477a7b9c083a4167ac31803c6" },
                { "br", "b653ebd7d37a84e02e89bb60bafc63a02a5f41e601c728aefa9a28b96a2d98933b5e0078309d5bea0a3f178eec84aeae1c81deb48250fc6468951f0aff2d116b" },
                { "bs", "b1addc8be0297bd286c048929e696d5ffe645c6aca03a5ce0b5dfa4554771433da1255b4e531a95ae534f05cdbe36bf3383f289f3bbf87a15241be3642834d1d" },
                { "ca", "ceee08d43396f9b77fa583a2cd96027718a966775ef3bd4c397fd4167a07ea1b7b454e78fd525c97955fff06cabcc086cd664074309a65e8904354e62b8061c9" },
                { "cak", "2fe26ec84503eb6e55c0af9e9b424dc6603840b0a36360d588a577873012acc7309930c9aa5cd32500de4f7281a4e732156719cb04d86c014b758068fb99a3f5" },
                { "cs", "457b1e5011ec5cadef489fc33e54e454fc2d3dbbe256fec0089d259a1ea133e65cdf71a4a5b1a4e68f29b9ef3d20ef7a318bad6a37ec1ee079efa2e4345215e8" },
                { "cy", "d9790666583237b2ca9fb283e46b85b78770443d606c4e55fd55536ff93426f475345894dc294d36ac556411cf5ba0a139ef7a3bdbee7b1ac91b0e29b4ba0ff2" },
                { "da", "800443ef281231593e375194f1e3f1da55eb449df28e43efcf110c6c7011c5b02b5e5e3c670bc9a1cc8f5f043228647e5bc5fda3d68ee2d5ffaa384b940c5d6d" },
                { "de", "57cfa8e95ced8bfaf9d63e48d6785ed7368ea5d5021ec216ece74effce01fed617eddbd90c527b88f507542fdc9ccc300fa6fa4de4f4c465419004aa7281aa28" },
                { "dsb", "c92c0629c4a11d7991ab11b0d51a3653d5a93455fd844b406ef9679b016e5891170aec53a3451ec57e1f410c80728e06de245337e3d847e0c89c71255cb7bd6d" },
                { "el", "0bf02e2ec70ae1e92543df7e71092052509bc2e4a378510cc009c5f36a2910fa8b0c64b44a37c4f0eb9adf0e538695e3c808eb4b043017f18b17163fd5056910" },
                { "en-CA", "a77f8fca2f441e0806e07d8ba34bebe34d92ce271d09c40d2fb4df04653373b8b16f3bf398103faf6dd596dd70fa465140700d132fb3e550f92507b36b274b19" },
                { "en-GB", "3f07ca9e16b64ab3a97079b723cb33d61f0de295315db94eb814fc0b93523c87abfdaa02bb0a11d252298f1072b70742b5074e6bf7b3b2b54f52f0792cbcd0c9" },
                { "en-US", "fabd5c7608aec3d6945c2a2038a32cc67b159bd36997598725c90cb042e86a2570a97cc0b1bb4763643ab42dda71c00e4fa242fd52c63b57c6cec9d70b3c1aa5" },
                { "eo", "963c59d680ce7d10b5a9abd0154712a68d746f61eaac89d83d00790fd5a62df29a3adfee83c19871c580d5af0cb27f5ce58606a1b1f5d533b55882b7e03b61f5" },
                { "es-AR", "93f9c41e47f4f517b97b3d177a12f48cf9002cc16c0500ec02d7179bbc59f761fab20a4cd39c9411b4148c83e24544661cef003e6cd9640997e061608a905983" },
                { "es-CL", "0eda63e62c2a6ebe28776246f5f459dc8a4957c0a953f5abe7982291ed2527170c6e8d27e0642ecaba3b3b7818564bef57564a2b3e11f07425f240fb43ab7b49" },
                { "es-ES", "a3389a9f68de68072759ee78adb8bc36c6e41183bb9680e766c6b2d83f3faf3811df2a83a5eddf0c551aa1271ed71511b614a8e11c03975e8f0af4710ab7ed95" },
                { "es-MX", "c951ab3231ab97402a47eafdd0755550e700ffdaa3f7c5821123af7c348b3636e8048084a855759a4c89cae14d6df3ebdb97134db33c81d4a95cf51eb3b60b7a" },
                { "et", "6952d1cb6cc34862bd8fbb30ad4df4ef20ecd2c9c9c14a4ffc0aeae2d328d7ebf1816f832f4fc3c9f312580f19c3ac60aee7c15c7e23fc9d632f0a1162df282b" },
                { "eu", "136f92e6d8fce3194cf36e4152cf256830c3a01855f1a89d3a930ab9fe3d038ac7cfa7095cdd43224d85c5cc58d6aa73289d72889d2563145b9e4338f2d228cf" },
                { "fa", "f744c2780680fa630ab5da5f1f04ac783c4d904be343003472781d70d16781436cd59daf12c9eabbb4898ddc28eef799b7447bf2ad683765ea2e79c0f89dabb4" },
                { "ff", "5d9458796b01926300e11345bef0c42223f31cf964ffcaaac97b6a8dd01a61bf2f7f695fc6e883ad10180f4f83f7ff4bc986c60a180989971e4a8bae8dd668cb" },
                { "fi", "b49f4cb839c48efd20b075cb476e12fc9c01e1ed802bb230945d1f72b331200f065e3d1574042f19713ad371a2991efa172e8d533f3e237edfe1aa4a7a777224" },
                { "fr", "fd689fe11d73458e9630dfc60ab7a9d0cdda81723abc88ebd812cb38f754c852b3c4298400302f24c06897108717b8ed17be11f87f7d74e5573fecef1b8928e3" },
                { "fur", "4d721f13e5fde16922b1616cb3fff5dc0bc37fd8f462ad2559fe5569d645d8e011a5e9c1b761cf7d9046e9a894ba9b23ff1eee599c898ac3f99a03696216858f" },
                { "fy-NL", "083950be4faaf3d69d5cef1735683ff3c7b3a33435dc23995a8f8d718c80c0e30097a668a467d01762744e4c623b713e87d5fdbfbc250b78c948011263c67d4c" },
                { "ga-IE", "d921766f9b85e64848d866f6c663d8738eeea1f6c58eaf92ea8d569b776a37d7260493a9cdaba63ac0c9af36ada41fe116917142763e2a10acbcaff686d05882" },
                { "gd", "b7fcf6a145d5db17fd5e74bd1d8db1114be26a108c16459a0011e39394571735e0b8ab5b4b8d2d6c88cb09a3862d50af9bb15a5b0b02850c937f10302f7e8b9a" },
                { "gl", "9788bfb9c8fe5c61c3f6d1af6b0680af260c2cb5296fdc80fcedd4f00814fb617f0a394fefe1cb9dd4d8280c22cbe22ff6be671aaf269054e7a13bc2cd09aaea" },
                { "gn", "e5052f714d4f49ce884f644e2bf2b770935b0c9f4770d7c832aefc191e1c1bb439d99e306ed9cd7a078e290a8205f3936a430a1eb332880a056a6838d393c59c" },
                { "gu-IN", "1a7ff60302c6d83e4d7290d09e36837487421d86217ed72ba8499d82acdc9016db6a6bb0a05cceeb73ce9b9f3ce5db327e158d5a6f97910e8ab32d740f6bf678" },
                { "he", "0065f46daa035f8a50c1e2f4154d3433bfab6f298fa49f8b4380a19ca08adefc3343edf033034f09db2189c73bb641265d297deb31aceb6e9477de14436636b1" },
                { "hi-IN", "efd8bbb969559011ef5cc2f16e6ec2e03d15aa0b9836f2a440c3fc0726f85feb451d29669cb595dc5173d3f40becba561868adfe724b06e1bf92540db5918a3a" },
                { "hr", "6361273755790e648530366e5e24f61fcb56e1079f84bf95d202adb1509380c107203e68cc88b60bd8497d25ac70d30de5fdce8d58d77c1b4f8eb6d4a1795af5" },
                { "hsb", "8716d1caa3e0f1dc22c7e6c728268e0083814c94f31c21fcd65e2be85440850f4fef1603bc21542297c5d84fd1960babbb6724878c9a6b958e5f98398e4d58da" },
                { "hu", "cd9f3836d95c8c9bd2882f0db8687a21fbd24c1e90f778109cbaa1fa577ba74a5b21c87c9e4e9163b88890908e2efe535581dab5626366c0dad7d1adeb25b095" },
                { "hy-AM", "0029a894c3fe83a22c2090deac7e23f33fa4a4c3ce041320fe0c22d69e79ebf48a605befa297619e4d855d4be2c7a7ca412bf0177de1056d9eed498f6505ce3a" },
                { "ia", "c6a12805da2bbc269d08919424956a89c7c6419fa67059a92e1696ca30499f20038613589d144d2afe722a06aef35b4e9384f838ecba19e613607d7813880292" },
                { "id", "effe3d4b2f4dde1aa5c09dd7c02bc4fb5da3c70e8022454ce56f7bc5c8ac162abc24efb84a9aaa74034b11ea5c4cfd707e54ae4bf0a40731bbe4cdb33cbeb4aa" },
                { "is", "4f2259ec0e330f1cde1b441c815ccbe82c04f1fc7e4b0b007f07eac452e952e6a90fde7cc1c7e5053832425fdc1a1a24ca913954ac07ec140ab58ae08fc1323e" },
                { "it", "ebcfe6c1aa5901585598f737cf9fd460f3456803a144cf2b36e06e88e38c40f3868cc712cabab0cc0b63f2e54da2e932bc4bd54e05e62f0473d5b968e678ce74" },
                { "ja", "5a07db4db43ecf60adb432d92036a1d4d257b7f2f3c3ba0c36b8244c8ecb89a773981777d76cbe16cc1dd2eb2345185e7f8a48a36123f7d5fd2188bfd24029af" },
                { "ka", "0e6645915e3e36d84c976becb0e1577b20bf8aa9d725ca654948c6b67362f15bf258693c687199647b9aa1ac5bcc2277a0a72997c34b31ad4683118ff184bb46" },
                { "kab", "c705c5850f9ca22504b821230a2d69b08406a89f98e91c6c37b931398c5284fee96afb4db4770175d75c0005437134889c4977102f7653e1d75440e3cc549396" },
                { "kk", "a0022cec0c243e1f7c848b678465afb5a1be0ece99325688c861b6310a74b5147b3281ee60d3cd29a2ed16aeead4996e720229a181e7436b00172b12700ef37c" },
                { "km", "dc92530f7a69590c798f67c789b731e01012a2216f977fc840672b57730d82e72533b4ca93020cd40036b103177afc437360b2401f0a6d23190b07c2134fc8ed" },
                { "kn", "aed6dac025406ca5341d59d3f31c305caa1b6f3aa8247e98752567d03849b78b3bc1d354fe9fdd1886a48905d75c10bf7e913954afd47044304cee27476dc7f2" },
                { "ko", "6a988bdcee5a0b098c255028b1358f9a8981f525d5c6f792f12231772b8fb8d21d8cd9b7f52a1fdabda228c808cb649ef24e55cbe87034b1228e32658ac3a437" },
                { "lij", "694234f6e76f3d149695e044c074f44df87eef3aed82f7eb0655ad75dac933beb7af1e01e8799d55be6610df547ff50b0a9edc93184d1d79d84f76b7b795fadf" },
                { "lt", "3af9e42970e91430f1786b4c7adb2e9904f25f76d9d3308a941177580cda37ac75393b5578feb6365470b50e4f0c77691c083de7d29be9fda9a0914a84d43831" },
                { "lv", "d00a6251233e4248fd44084a5c460744cc1f3814f025e44b412bf5d1330f9a117b70b702ed7d31d7ad36a0e9c5ec40f59f12c0adac3107eea91e3caf3aa3bde7" },
                { "mk", "a3a1bdf24943bea78cdf3467f472a8f039a6c52d120b2ff1b175c1d21b801eb78957a6f613667b83efdb3032d6cf48c94072496f5263c173a74d748183ca27b6" },
                { "mr", "15e0d37bb354117cf153211b0322caad3a8b6127476031560b0e3219937c7f23bc22aa721fc0438beeda77a11a91d531273f4c639685becc6311c25269150b6f" },
                { "ms", "d304bb0776bc2d46dccf49caf3ab841861469e435bd4aa1df8cbf40e451b0d8de10cb4d25a15fe748aba92cc550199ac91e056e5cc67f4cf1c59946b0b6a979e" },
                { "my", "03763c45ce707fe5d30b9c7884d7f0130ddac8934424f9336b4329ed84a9019fd832d398d61ab4521ef43882109997da14ab69f4b699e83e2d29b52dc677756b" },
                { "nb-NO", "beb73284b5cffcac27d84d9c0a7a318af8d80360a5e06f2f8a8887cba244cde2122075699703235e01ccfb4812df07c23c7d371c36aa919871bfe0569745bcb6" },
                { "ne-NP", "256d2aa213b0ac8873f15650fe20a193f73fa9b2b601fa689011b21bf0ae7ad0e2d461756409a30bae020ed72de647a96eae08474f6adbbd718fb4b33d5b994c" },
                { "nl", "2972ad0c7b5c20d515a007d01927f11ff6763ee45cf4ec545b8b74fcf496fb1a40fbd8962b52d599cba410b23d5f9ced487c82e7d3d0a1e98be8c3cd7601ccd0" },
                { "nn-NO", "8d00ce8d2b64ad4bf7c491ea5c7e20d472f0ca5163362c440a4176055a4f96d63f3b4c0a8b1881d85cd0fc8246b142b5f9ae5c2ea01c123c8753751334de0f01" },
                { "oc", "7b04b0c6b709e5a201f97d885a1d05c18bbccfa8e94cb277488d1c2074a5ef9402bad8bbd6b2a2717eecd683e34c7ff72a0174ecb6b7902b2f8d5a5df189f774" },
                { "pa-IN", "fa706275ac1e912edb028488424cd614b4520962ab264baedccf0d5c0c53dd6f96c0363622ffb00f2da89c1abcde7695d6a72c30d4dae223d2781dbaca296232" },
                { "pl", "22425b3db2d9e57eb032e8bcf90cd9a375fd329d321ea3fbdf8af307715a803772bf720185ebad583e0abb288527e78a556b4773a68738cdfcca0c1089b1b9ba" },
                { "pt-BR", "59649b84047116603aec86a75f71e0a43dfc60b93e7f87631ab7f964a10ab3d88ec9813e6da0b57f5e1f6e83a04db75714cb62e72ceba5e08dd6cda54be29bbd" },
                { "pt-PT", "5862fb2cd2deb7aebc50fb5cc03433936e166a1268500782217fd80fd9d67adaa5ee87590ba8c9580dcd7bcf9c3ada1092943d5e5ebbe35ad440580e3ed06496" },
                { "rm", "61c7b4508928b75bd23a2cce758c8ccd53cd5cf57355f33a5d22a880b6aa34834a8fd166c6dd23ca1d77aa2e70cb4ad189a28f6e2413caf9585520ee8562dd03" },
                { "ro", "80a6c1f90be4992a4a57d6a20388480cc00ec26bf5ea7a96ac006c73c6f410655bf1c1484806dbfb191f69218ee600c7444787c0d02dbd3a47e4a3792d4b3cfb" },
                { "ru", "8294e14f7ef2349d41b5883a7b2bd95e45dbb9d28ce8becaff52547f0217f455a8ff09e7031d1d3e9a8dfd83210e1bb99b155c44a6b60b11d91f859617714db1" },
                { "sat", "905fcc76cb1cce0593ddc14b2f48bd38a1391ed25e73c18383f1750b4bf8957b8b6bc8fc3cb7cb49001f9df8e68c79c0c776a530b9319fd1948a90a0bd728278" },
                { "sc", "5a3817d0a9c47d57ab05304bf55c38b5373af996f1918bd82ca9f65c1ba19b6d3dfce2dcdd9fa434fa32d58d03b41adc3eaf66bd3ad23af6223ee9ce1d65159a" },
                { "sco", "027fb673b2ee846067deb25101493c77d8fe85d3b1f8ed4272aab9a8f23f56f5bc424c962d3fb237b96e4d7945b3e353bff8da9fe18d8d8e42d1b05da0ec0032" },
                { "si", "f16d3c8d8eab220213161cb261539b1906b2e5b94bdd5685b6f9ed52ef57edc783f325ae2bcf4d8ef3813de7099765406722b4a8d44228bd7dc0f8d6d439f068" },
                { "sk", "8daeb2e694cc74e691a66a4f6d18259e70f597f07025fe2efe3d76b9bed9ac6dc42ba612c5922b20091051ec8ede1a233e2590d7da9415af1112d234850dfbbf" },
                { "skr", "359bb59da90d9a7c129dcc250a30fbc9107cd8775cf29ac8a6ecbc6bd7c22febbe9a104e3f1f99b5d6b02e683cec5d228f650d3097588d092841b7179d5df69d" },
                { "sl", "3a1360341ae63373e3abafeb5a24d8ef7d0c87c806bd09041268a2b2566730fde715dcf66236d45c30d797daae02efd35981b66b620f169f9bda60dacb107181" },
                { "son", "7cd91aabcdb0a7fef5c417bc09290bf173f98b556413c1165768affafb9fd05483df395961be168e8f10478951fc55d9795e0d9b2dc5367f8f9b7f2ecdf1d1bf" },
                { "sq", "04352a051b5f39c8ecc5c6b0e11b9eccff6520265bd3bb615d822db9dc1b8fe6431e78e6a1cee99ea4683e175600b793fd3e118a7525115ac1777da09ab7adbe" },
                { "sr", "5dcfb017a4bd1e6cac14dc239453f8ca2332574c348acff36a3cb980017fd8a06bb788c8c1c4189a8c0b7f982253a3b647abb67f60a63a4629566c8b04ba8513" },
                { "sv-SE", "e5365bb3e0a6cf1791260066c0d5bf8f28bbec44afbda086cb31124b768fcca4a9de7fabf5d2026382a94a5f4fcac139101e0a8c11039dc3682b76648cce39ae" },
                { "szl", "276844a6ceb1a9ffb3dde1f70eb46572454ef1f0f3c510dc99c4eec7fe6d8c73d7bbb3334288522c0a62dccffeeb7a1ace6168d059f9540626b336146632b867" },
                { "ta", "bd47ee3dc38ac087b17dca0d740511f65d2cfbb688199b1e6034fa460aaf2b15a72659c86cdc2aa849bf68717c3e28aac9efef39066f9795c57bd7da583aca31" },
                { "te", "2438573de21f94a3d62142d05aad642c7caf4b976e27cba4069c5ab4a1303c9283612a2020ba3f4561006b48639fcdb8b43ab8b8e76fef898d108479a179b5cf" },
                { "tg", "0f4e0014dfb40b8a3387ea995443209a96519f871343c2a3ae9cc974636a3ee22e1983b7230527c6c8e9041e4b84b77bb837bdb23eff2672c44169cec1dc2da4" },
                { "th", "e8246f15e9c425e535732fd62ece4826807de9e45179823fd2998614841d41c59a6271aa7fdb3b36eaca837e0355bf3798c94002340f85b36cc3238492da7715" },
                { "tl", "204bd9a298ac9d0ca4396442702cd93f3dbe1a0b00456144b1bbc7fa794611362f28beec622a288bb783c2c06dd2ff80adfcc679ece822ae596eefa6137da553" },
                { "tr", "7e4b266d4749ee02eaf591d42aca8af15bb227dc79a34aa5890f8bd6b4632bce48ba12edf16f1fcfdf9393ad44f46c67811a0e1042f5703150ab4de74a1bda90" },
                { "trs", "79f5993be1444293a082baf9836f92a0218d1d57de04fc80d9ac41b08a46e77044048b2fae09e9f6a8bb3ab13c19e4b64a2efe28c228e81f87f99f38757cc452" },
                { "uk", "d30a5a0746c254022fafb6ab0cffb0b69d58f8966bb4ee6b30041b83514160404a8f76fb9946505da9c413d735f5e764ab1ab867228a964c89861a61b679d229" },
                { "ur", "66db79d5d10087c0a80c50d1ea51eca941e7183ae9f5e24daa72fca28bd5b1e715441888996c773e47b7515b94ffaaccb64c9c34e739ad9057da59fdc3b9a906" },
                { "uz", "a0f9385a61cfb19b956b017d1d1b8a20af2aaadaa947b395f1bf8b46f1c627d43d797c402817a2ba066ecf077811fed94bbeceb7ea7529548bc4d63db04dc852" },
                { "vi", "214588553ba1115f2c2a82fbf11850958d8d98c3e1af0b3c3999b73d96239c0cfc9063664e45dbd0b92fd6aba84cec38b22be1590dd7e1f32cc5588aeca1f4a4" },
                { "xh", "13ee4cfa31c794c07310c68ce7cec6b61747cc34df346ad1d66e55edf279b7f4a63cff97100ece7e1ba3544b467ab3214e74aa43d65730c2f3f7739dbc25e867" },
                { "zh-CN", "ffebf533bd57f8adfd7d4dc92567a68d52c25694cfde5fe44bd28958ca7d4a0729dd5e37d83fc95135504486ffe43897d6328c1b254dad82631b0098268bae6f" },
                { "zh-TW", "f997410e0be10f915cae53ca3a8d2f8a15efccddd3f4c403cb31196e217328544e4077b1598495e6881e195d9c0b6551a89522e83a2b0073bccc9176de39a54d" }
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
            const string knownVersion = "159.0";
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
