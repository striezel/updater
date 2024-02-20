/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024  Dirk Stolle

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
    /// Firefox Extended Support Release
    /// </summary>
    public class FirefoxESR : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxESR class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
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
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.8.0esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "00817018d9bea5dd8e0c2d0c707b2bce0fab36ccc123a287fa2e367f5fce20ea33e51046571f16e80ead4db109770c274b530fa7e6e87026668c2546f07c5d73" },
                { "af", "dab8d9fc3b0fe6c43af42bd08991c4438dcb5fd17c14d13151e58c65653db12fd5f47296ab697587e44ad3f097f5bc74b37b8b4c179419be6dab0f3f4a7d99cb" },
                { "an", "a3699bbbd655b1e674a7c7d38e2b7071b4a2e0e50a12e48d79eabe33767bc2156ba48339698fa6717f361643ae1879e42df5c116407cb246c785eee2192cd592" },
                { "ar", "b3173a0edd997859fcb74557fc455a2d3c9f7055f9444034d53906767e45305bd7804cc75e86de9f3f191fd5985fec1650e10761927d3acdf1a6238aca9a3c1c" },
                { "ast", "b2cb5cde95ee00666fc26e9bab422aff04e2e5b2c745fad383e791ae0c28645ded780c073ffc91ff74c92ed34966af58ceba66d6c8bf4d4c0602b183ef756f74" },
                { "az", "796d117983e3cf160e6b91d0250bcb19ee746d8bca59d7b94c91adeef9f971f718bb40752e7a8dd6d5708ddcfbf845bd04596741d128e29b95502755e73990cb" },
                { "be", "174e22ff8546e4a8371df915eab0011d85c63738212e9c8eba5dc3beac9ab2c68e97c2720a2465ce255091aaeccf93003d9aec92c9e3939173882ae5f571addf" },
                { "bg", "71a81340961acb33ccc396db90e64687b6d2917939018f78d66c56e75adf323139e4d646d32ff8fe34ee56bf950fe23769f6e3b3ed8827e06eb4b9f26ea7c3ac" },
                { "bn", "07776e02920165fcd52ccabb07a5f2a5d0741e2ce167bbb6d30957f9603e5f4e8e0d63e3e04dc2b67f692435f8f3213a636b5be3108bf43b6a10eae7a1c736bd" },
                { "br", "d0a38f88c45c6b6f58e08a514c0695ef9703e3c9d53e1cdce4680f5be1dede6db384725466ba1fd21c5f48558b2e7cecba0f24038385fa178d50611b7eb73e93" },
                { "bs", "d7b108ab542dc54b88e04e2f8909a36e29287f428e3a2411bcaace7492398f0a1c57c5f39958e74b4d55a6a9e0fa1c14fb03c8af3c64c8b62ef61041f5f59648" },
                { "ca", "74b8d257773212e2ea80a41a3cdd55fa4cdf9d80a44bbfc18897f5d68701af432dafbf7baa7e4d40013921aea184fdc63d899e8c9f0bad9966da451278a7e13a" },
                { "cak", "4f1873bbc380acf6f2523f2fa238f6c22cff59ba7755be8985fbff091125e73d7b950d73dcaa7872542ae95178cf8dde2f59165a077765435c72b7a92daba606" },
                { "cs", "be8cd8aee133127cad211ffa620487550220dd1ea23ee2784ba1e56878905785433be01f6bba8170f52a2b98699ebda1942fbcf20b2bf680460bd9e90bffb733" },
                { "cy", "de38663c10dd835867212f7017d1c62ffcbc9c5d88ecfd5a07efb44ef91cb998c530dcffe96fd264db0a3f0cdee2b43b5a46d5258a1024ac9a91df066d9e9f2a" },
                { "da", "f440110e0905c17fbcd77672724a3738998c7c6cf2da42fee30bfb8a2cad0fd9b09d35d205349a086adf99cb7f60679fffe9a6935d53619503749f5732d2341c" },
                { "de", "537d6894c757982a7d9b055920787320258f924b9572465261ea2c6f297ea380effd4686a0ecd18b7c8f8e6edb9198703cb0c685fb5d463759e62af91dcc9d0c" },
                { "dsb", "0ee3b0562c4feaf6bee91c1bb9443c301b40bd4be6a293ceb3740cde128d4d6eef203e8383c73e1cf097c5512172316b2bfb4e65e5be82f863e264b18956a34e" },
                { "el", "6569a2a7a0681cc964aa55bab336d72e534c3234f289d30c3116679664d7ace6a7d44a2f0227dc1badb52aa669a42083fcec6cfd04344d5f0efcd7d76c0fef4d" },
                { "en-CA", "6bc144214c7786765867e5141ee0783ab296fe0c241c97d0abc930b78b1ec10a692f78adf7030c6ee61cb8e41fb6489c3e5f0c60ff97df6cddb02abaa9b3a7b8" },
                { "en-GB", "3de6d66abb3ced0973e4c9d81cbaa007d4254fe354ea49ab6733768d89c4556939a571b5cf03093151e7b92de501abc7068d834d495c5dbc8c305904b5765d50" },
                { "en-US", "42f4c064cb11d24e5b00a5f10c950f12b6559cfc30d8c64e93d206b40da199a873c6e2aad71011d9c6df0e5a33abffd98dc12bb6293bcd5c7639b1946da31ccb" },
                { "eo", "bb8cce0be86879c2504efc9c981613ee30838a53aec31d0c4278767ab5e8f7dcd2bee68e5fbeb15ba2589c6fbec7b69e0fa1f1624e8d60b8ed940fc648a0c291" },
                { "es-AR", "e29212e98620c441ab3feb133738bc34289b568ce150507d2ade0f1594305ee9d29ddc0e42c4127ea8bebf7103a32b5989d9a9ea83da43711da2a83e7e541ca7" },
                { "es-CL", "4b9035672739627ed06a16f742bdfba1384535dc217028825fcaa1ba865abed6c3bf64ffd01626be4319d6927ba4cbb859cbfd367a35e48d64c9a72f9664ae96" },
                { "es-ES", "25a247c791f100a1b088576a67caae2558f54d33130cb69e22920409408fc73785bb0e557809528fffcd95a52c6ba2a8d7291a5bffe6a0a37e08685b329208c2" },
                { "es-MX", "5b8e2d9bfa4394256fd07fd321e09f0c8c6ece8f37c50ff139d22bc7cbf415d8443fb92afb2ceddd448bd82a3be7c13dbcd3f46c271f9d6f722a5d711b4d2202" },
                { "et", "256c7b37dd0da4a54f20d367bd0dc359b34cfb96a68f02979ad187a108d526f4d05cd336847afb4ae1500647cad306bc94d2dc72a07bae0d85aa29f173706411" },
                { "eu", "82d5c06e8757b0684da2fc54ba5152bb61ac28b7ca9fa6be25f65f1f8da38c7acfbfa64a4f22e4858cdbef43ce764b3ef18207643c24a2d2ec143bbadfd15e7e" },
                { "fa", "681128a02ed4af76edcb90397cbf322f1d4cd3e3df1eb25e5aebcd94a66e845b55e3d411b3cfcaca89e91bcd2a63f45e4faac82f0d2b2988ff8e0ccfe1277a06" },
                { "ff", "de3f02f903166851c57125b34db91289f1fcb41991532d184f3c00eb43d24a9c91b068abc905d44a2ab376e540ffc08eb6d8bf70afb522b24751666c91e2a598" },
                { "fi", "38ef1561586594da144031da8ff131743cde607544f8bc486c5b0bd23f5506f7d788f8d3f3dbeb2d3d1f1b0dcb80895e549f838e0e8acf440f870928fb6c3242" },
                { "fr", "c0374fe88a8088b2253c0252405ccca83fe8df7c6997b671dc975aa9050d7dcf5d22dbe4e927878d54e7886785ca2f0068925cc64b08ab6db69b9bb5dcb90c16" },
                { "fur", "2161b9cccac4cf9cec9248aca74d65e984a212f72ba266b61c6db9fdf033b15b5320450b442904ce6bba2366b8d2f33ca5ae58855e5788cdc65afdfe7f983409" },
                { "fy-NL", "6abcd6e5bfe697d0a29ee8225f384fda8ccdcf7b35352a1c0ef13a225c1b56d6d4ac05cf7ace02fd517188372ca7f6c9b611304c786462f6ffc0f802049d0f07" },
                { "ga-IE", "fd517f8a30bfea24da0f2c7304b10e39f8aa4e0425718bb20900bab92ee66bcd3faf210534a1a602adf766cfe9c87808bb8f6540823acad6e5cd6a149784703b" },
                { "gd", "259ddb0ebfb2427ea86224e4c019f89052143de2eb904e7a1a8176f2604beb18161469ed7c48079aad6aab9433480a91ba96b9148ca2ae8e9ce6e2cda8680f02" },
                { "gl", "c3c89b3e30d68c19903e16dd766df1221f917df7d788849c2a7c9e6e4239a532ec0d143b0febd2053124e5d2c185559f1161f6b71168b9618795bc4167d6ff23" },
                { "gn", "506de00233c089633b7349996d34788122af61901dcbdeb32d9b60fa5727a8b3b42b76ef89509ee80001352f4ed28af3de8efa8045b4475ecf7de605c3ad20af" },
                { "gu-IN", "1172d4fafd39977252c60d19e3da38ea1783dfc824ce9d4a7b3e3faf5ac0ad313c67271d1bb7f70def224dd8573e907b3a9fe7f11cc2a1b8f4ac806ca2c0ef08" },
                { "he", "74716e910ec341c5122e448f64fd6a66a21559bad465405feadd22c9c38eed2e5c251dc0e1d137c699bd256266e087d7d8de486b0b0bfae31205de32916f054f" },
                { "hi-IN", "4b5277af5ea278f4531e18c28bc7446102525f4e8bbc980bdefa866b2018e8daa96e7298cee882216d87d1b28f617404818f762831170dba47e408da5f63bc18" },
                { "hr", "90cd57d1d0be5387be03e6b6d50c93f09668d12a1581317963d364d9c39ce7f7317f418c8229b29d72a49ca983132fce58fcb82ffa8416e10427ad7ad21fad6b" },
                { "hsb", "a9860d08282464cb0a43d2adee7d356bf0029b5c1aebacede9be69012216d6927e3cebedfb5c73bf4040ab094c4a2f203a21f77b1092ff924c783b590d41eeee" },
                { "hu", "2d7a77f88523647d7c459e81bc4377cad7f0fd94ba084d3037e4d3d76d5c46953f3adb42c6deed21cc43c37e044fdc71bf5054a87e05a17b1302ce02cd36e924" },
                { "hy-AM", "8a05b0e2d4bf045a88409dcd545ab67300dc6062f3bdbe93b14fcfde2f8b2a5d7031952122a27398c9f43def246c83e19d8c62e8629145fb0204c3fc03fd9f56" },
                { "ia", "31587dbc8a5b2464ef4d894d3c7cf555b35a8f5b4bc99e004557e8f42fbc52181e9cbd870759007459fb902532d19fca5d131c17e12ec8c634c3b1cd0e565508" },
                { "id", "5f03877a4d2441e8f6a8fb80c4f89423d831fb7fd5b2f7881a3c1705a304985e12d8e18bf30a60c5cdf54d2e07765ca59fe4896978bd7e61804b7e06c19e5050" },
                { "is", "403a0db5a064032522af14481d1d9de8d95e0931dd139e5954578d2a96f8f3504c5c40b2c8a8331e8ab30f80fd936c6537f26fbb63693f08cfa5426608243040" },
                { "it", "e492602afcacb8a0839f65fdeb8dbda8361e95c0ee64ec425c914c8f5ea4022386ab55889046df50c787457daadd2d0bbe707ffb4d2f190452c2f3064ae5b27c" },
                { "ja", "e063d86c2272243b13a8673a2f29c9f3bdfab278a6cdcf85e16c8778f0559f6333ca7a169e6d19c41b273c3dd18eeadc2eb241d4e4767dbb3714796c8c5cd55d" },
                { "ka", "77da0f237f2ef32ee7e3826bc089b1517fd7c7dd53e20391aa38fa419705c5a2db2f04c0fceadd2c9961cfa9fe53c999831c48bed545241cec19c50699ef59c9" },
                { "kab", "055b9573470fc3fbfd66edb1428005253cb9417bf15b08360d85759ff787cbe2f752b40cb91bb82e33a8c4c7d2f0cb78170f526ff3fed00226edfd42c70e8a86" },
                { "kk", "104616ecce273b7655f75e155f5811f5127a5c51fd752430efeec5e6b455210752e820fb57322af32bc047e1b876d87a87161d2769a2808b6fa606727d24c57c" },
                { "km", "1f0b2cf701bb9d383edf0590b795be550e69e428653e404e2064ee994d3e710c7253bdc96509b56f4e5250d070c4b83187824f921567bedd3bf5461619d52c56" },
                { "kn", "a661ba0966684c8d31c349ac31c4af409900f59e0d4266625721502e770585cae607eb66baee1773509f94b1fbcbfc00f03748c5a2b19cabcf75407ed33308bb" },
                { "ko", "637ff1e103b7896594eed74050acb26eda7d547d384c72b27ceb3969369dff5c03832dadbee3594d3be29284b3d6e8f24530e52efc2f0b75f9a88f47439ca7d7" },
                { "lij", "fed8767b1a59b66f69a72827df239591a2f6ac98ce92fbfc706df0503cf5d03fd59ff90213516f91fa6a3c52fabb594d70f4f4eb2d0b1b43b8d6e6f1e43b8e3e" },
                { "lt", "178e6b486fd6b21012f036515ae35cab51df98ca3dd5d037f553c6384ad82a8ca54975adb74980416735a1fa9fb69b4e67f74850287c59b47eb48b62c9663883" },
                { "lv", "0fb67fe4481017103808b0f592972e5410d42e44d0c4cb4b2d2a115cc1e6e3c06226576aa6a006a846b55ca6403f564c435f4e633bb816bfafb84aa3dd8e319f" },
                { "mk", "5ee49f1f18944bcb6c6e9be9c8b29dfe3a1c716f09c09da449564883ec1225e1ed2b2a23c286a8339f0babed28424574ae2b3e43dfb829cb2daa7b728d057f19" },
                { "mr", "fc9f0ca47ab12416ae05e80f42389c72c20dd785f22d9ac2b3a5f0185097668d259dd38a781779725d7373d21bcb8c5e1b25dd653142027b42aefcc5d7cfaf73" },
                { "ms", "f3f75105ef7d376d09d9eb0ac9d2d21638b4cce18439b330229baa7585dae217866ae27e44dd870a6b63bec61d928d8abbde595fca9c66e8ed8300b33e576a5a" },
                { "my", "6826b2c67d64968a17e833a094981dea3c63311b70b624350c80e3173d52688f97b3fc3bc0b4aef3cde0a4f27bffb20c6c759f39fb32e2758f16048133cce319" },
                { "nb-NO", "8f60678498e6f350f4b0ab6d9d30fca060c8ca37e3a93653f0e538d100155cbf0bd5de819e71e6fe07924d7cfaac9c0dbe9a5e059f85b0ddbe600c6aa4d7ce8e" },
                { "ne-NP", "1636fbabe50ad7bd43cdb19cb45d482aeb9df6ad9b3caf942ddd11ed49e4f009b74f6c54f30a4f1d893d2d0a2c1f38fe09b55a5f41c9bff147f260f0fad82055" },
                { "nl", "a966e9999eb8d337df38c3cc1c593a667f44702f1df0c45e0437267febeadd6da3215e9bb31b3c8846619e6aef965afaba1d88a573b38b3e87e5a3bec4ef69f8" },
                { "nn-NO", "ab1199892b7f57b48e0f7f2dcc68d5142871b54580c162852b21ec3490f07543c5f1adc14c8cb97be750c4926f5d274644e96e453cfbf051307d6e6be1037c71" },
                { "oc", "83e02ef0db1d134a2c263f732509e75bd733807d902e982088da5a6abc59987cbb290414dc5cd76945f142c9735b535edda52e09961b78f647b3d5fad2ff693d" },
                { "pa-IN", "145dc502e67c74baef8b1fa1750c5d6d991a0afb374d31cd8cd4464098316b7f396779ee6d1c2046a03a3ab6e176b9743f66304e901a362a4479e269fb50a3ea" },
                { "pl", "a51ffb26fe07dc216c365db2dd0b6938ce93281eef7cfa1c3de4a7d3573e5b69366df92ef688928e28c236022592b616c23bddd02c5f57f68bff2352026a3373" },
                { "pt-BR", "39e3a942be62c5f07250b462282c3ae18c46ff5dc00a5d236f511b62fa9c012c84b20a417b0e1223d30e5df07a83904ec1288c87f3b0ddc2513d4cc8b5849cc9" },
                { "pt-PT", "0a08fd19cf292c6d2629d64403a5ebc50360606f7741c2345885f6e5860748ee3f2c059055a64ab7455b0ea31bbec4c31107906e33318c92c9f569fc00583706" },
                { "rm", "f1f953c31f9179e84395565199eec1b015eaa2f3d0bae002da523adf3888c0cf1127c32b862041c34f7e4e96d17f37e9bdc1c1ed77c5869a83886f71bb8e0495" },
                { "ro", "61b52120f5c968db08634682b46b6a8872efa9be8dfadcf5de18eed10a00b4366a6764cb3b62f8e7e3210973cd906a72c41a993546cbe7892b897da76bd87e39" },
                { "ru", "4064fcb26b357c827e7e0d6b6aa37fff3f4cc4d2820faed2a96549d7d3b58fe0c905d8db4d78c472ec97b14115a38f34ef17f8f824b42fc674175acc2111fc94" },
                { "sc", "cba6be959e048a91402a718912554ed1f9f6c6fdeb7c1581f44623833ca85927fa19fe966c084364e3aac09aead38fbc01897763970aee78baeda0e954538c7d" },
                { "sco", "72f79075b2546c37a80d0a6b49627e0099c10b62cce653370320a037d0fff9b9ee09d7d1e3ba089e728507a2297016c4787a06d2d511e15763a3d34e08ff6e9e" },
                { "si", "ab42c3e8e52675c6b96ec08a67fb517309825bfc1683b29b5b61281aa67d6758de4582cea1a32b5c235ccf2df728edfaa0cc6d963c9c2d262e8474a21cba5ae0" },
                { "sk", "3eabf41e856e203d364ec7d88eef6b76dbd1afe296c5b7034145d00a848cf1e44989fcdabc6a9e69ee2e47b97e64779e37d3e217cbf66fc1aa12d31fd0ecfb6e" },
                { "sl", "2ec4263a0ad2d432bcc3d952c235281fe70d402d063f28cfdc61b04f3c3bfa38a0174aa348a598de4cf398905806cf4261340b43e0619e42b1a5513e8b02f930" },
                { "son", "09d64426e5a0b06efbe091cb03ebbdfa04e5bda5b4a650e6a9f3e56829bad0965dcff589e17712ab9039a0b3aa223160c2239f753993a54ca70a01ae8c802b4e" },
                { "sq", "d365c5eec774b6bbb879eb7c57e9c9cefd87098b180bed8c666dc24677090de7f304d4b50bc025c58044a3284a2f94a45189d19eefeddd1e3eadb0e3522b0209" },
                { "sr", "4e21919279cced14d58013d5be6a5b6bcafcdd9eb718c48030d01577c09698106837d3531c7002c044ad5afbfef4082b7df208d98443cabbc3fbbe8d53decb3c" },
                { "sv-SE", "274f93378a91d36f57992435f2a9dfad1a966ce1e7eebc97684d27750753b3c291fd80c50fd258b984da073452a245f89c7e199b333e972664ad87af3c17de74" },
                { "szl", "3b8bf14a8960ae40e3eb174c4c9611cacced964ac0100a0c102d7b98608a32a0c02cca5079286f05b9ba132f16ceaf53259cea4dbf501be38504f55febe070c2" },
                { "ta", "4494892a8b9e0971b5360b443a421173ddeb60860b0466c35c1a10b1123d331a02fced82f1d8da8c9dc73a9acb1be1ba0601d7f1b19bae1ba2e2503fc8837e9f" },
                { "te", "0a2dac82fb716cff78dda66044979b58064a83c5c8a3e0cae34acdaa3c015ad5eed28c9b4b7d20e6b8d28d67c9c8e5a51452f1091f7303047ef3941d4ef51b3a" },
                { "tg", "61fd06faa8db649eaf9f13b9dfd43112cecedd9d7904cea972cb24052bc99db64e23a936f40ad7fa84b26a656f16bf659714ceb366d1635fd421854257d18ba5" },
                { "th", "235610ee0965f3b135f19619f90bb9d604c0a12b8d3476396bbcefc08cd01fb48bacaf42491278cc62aef9406d2b374b42b0e64f168e31cc4178cf63b4d51929" },
                { "tl", "6bed041612ae71e4089c1378b323e2ebfacf12be0b8fdbdd9b5d903ef4b9d3d3450b46311c0cfaeb2880661b8103fc9ba011cec83d87221a8aa851bd10363df3" },
                { "tr", "0c3f8baca22af82af1b0d02ac51efaf0f662e4cf5123f85123b2ea354f851913faff2a88013d3015cd2ede70b00238f13518a0f35e5197ce780483f6d810ef44" },
                { "trs", "2e07c5aabf8c327849422ddcd82523bdd0bdc69a9e6cb0588a4331eb0ac3f7bb3f991e3143e15ae8af945f6a1c6076dff06b9e3bdcd4941de2f4c7cafdc93413" },
                { "uk", "46d19602b0af17cc1501703210c58088744b3a474edfe3a66d5f595cba367556f66d63480ec2075dc39f5b41111f73e7787b92f9112af3bc612c1d80573e1dff" },
                { "ur", "4f45e1fc84b93a2d56e25c4f1ab756593cb5c26928d353e3d856dcdfb937779326118895635f0f7c29f92e4fad05273d1d741662df4cd7b62673d1179fa8623f" },
                { "uz", "52821d8b726febe55c800707e0146257bb65ef576dfecebc422d1fe1303e423228be12661b9157c8337256b85b9527588def64ad8391d53ab7910218411b816b" },
                { "vi", "70871c9786745991a5e564da3ad61bc5e6c99c7054415488fc13a54a1b076814310d4158bb761fa19f73451b8d3f1086b4a865249c2bf9292b1c48897c25e934" },
                { "xh", "a86ad9a4e4a1977bf9e702f872256d5fd7892e0eb8d564b0896f0c1f4a923e3de08189d8fc8e80232c6e06539331480ee26a78f7e3c643f1230dbd6aeaca59a1" },
                { "zh-CN", "b2091074a0e03a64920dda3cd84fe847d92e79ab9242b6eb319609b8cd85d09105db5fa5acd22833388af8312f4e9757636280b314152e596781fea0645b9eaf" },
                { "zh-TW", "04cf5bbb8b79a385f167b59d9a3eacbca9ccbc954af614636960e72e5d724cf312e933664579c93ab6bc405c3d0dbf66884e8e43d5d6ea96a1ac35d913b321a0" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.8.0esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "b51e90e5184007718e633d0cd8ed8a7864609176f9b0ad0df10455a996e2124621e95f561771e43f0b3e24e1f1ff212612566ff62a6f7f254b196b6d0830c37f" },
                { "af", "5c3ad6abbf9f8a48b842a638412c2c4d8860c0f06b03cc1dfe83e398058736648edd3c20c240fed88497aa80f26a937992c06f08eed1df1892cf02ee156da500" },
                { "an", "07a63c615bd6d11914c2b79675d374dc1d8ff875788fd150bba8772f730e595d80a167a9b4d20946d3e4db304cabe89003fe89135f7a4804589da4532c951fc9" },
                { "ar", "f2535e1136681b6be4f514b901ff6aac3a4bea042329241c54292592d9f32a36ee116dafd007cdca1f446ddbc81712fca1fb5d30777115e9a26022a85ae1eee0" },
                { "ast", "a6ff02d98b87be5b3b4e169ddfadbc7096b10a328aa5aaa956b8d9f73c280aaf5bee95a7c692bbaf95eea20453ecadd18eebca36bab4a5782b44590ab792769e" },
                { "az", "faedc6c781c00417ed714ef50ab78427d6f50e53c5e94c605122dcd78c41ef4fb4ae86aac066f57821da65a72028b1281c56da51f11ddefc8ec312196a446246" },
                { "be", "e249424a2b939929d96fe2fef1a82e0f662cea23e09b003d0a74cfbada74af849f6f098a69f701215c8c6e441ed75d6cb8acd2c4a19598c6d0c7be0a97e016cf" },
                { "bg", "dba00fa360bef7355b190881f067996bf1e8b74eded53eeaa8474ecedf1079c96f75995383380b70f0d66ef64fb2c6d2975b0afadeabc2b2054b6ea17d909756" },
                { "bn", "4916b2072c35d3ea4bda12e4bd592c523c5debc816e1c46ac4085a12406d59a95a58bfac914946a5827c607005d3790be689f77d25ec77bc1b908a902d996aa7" },
                { "br", "83348980ed2d3a1f757ae47b86b7252229c4f5005ac96fe5740454b45ffc3681e28e261c7cdbf2f413f22e564402b3b123a2a58ca64564aa56507644b8593d4a" },
                { "bs", "9dcebe8b880c0637c69db440c9a949f4a581ba3cb25840138f17faeaec80099b6c04764c93d9ccc40414bc8ff955ceb331d044386b69d142d8fd8e5f5ae5f69b" },
                { "ca", "28c01b66356a298b5903b06d19f7e191aab7c134ae6b13a4b47bfa54fc2a8dae3d958b5d840898a6dc7929b8d3850d8344430f66f8b84b68a1029949da28f9e6" },
                { "cak", "6674f7bc2fad11471405278c92d258050263d440c9f62b49ce016d5aa30c8a3a486991c79be0f0217999577637225683e06808498996e013a7bcfba13bfb7fa4" },
                { "cs", "ba12e8b8495025f017c48306785eec5b7f094f73c47f0c4462a18906a096bb5d5bf4fb535de361b021c15869448b58cabc54a524483d88461669dd3573cd1051" },
                { "cy", "34b2b59234bbdf00698bbe978f10ec34c95ede62f53add7b28cee61a578ad6421183a2110e3734bc1fe7d6839ebebe4147b9006a31d76c22e1566c82985cb4a8" },
                { "da", "76ac18f97004de9781b6392e94131de4e13b6a9b7d8c9fb6727ef32690147b048c7f5807da0db5c1d5877cfd746ad6b2a2080d0c555c3dd21d3305e3f7cae60d" },
                { "de", "b397fba51abeee19d99889a24fb4cb6a30377f3be8c5d4707172c96907b7a43d571a6006f71468fea7cc3a88c4493f90f6626a52026fe70181f607314e1b9776" },
                { "dsb", "4a369202e5d244dbaa065d309a5de728d5152263b2ca0daf932ed3010048609c06cb7d7579a4ecca0c49c5e2b209cc51971c267be7779effb984403243c83846" },
                { "el", "d1dfdc34624d5085c8b850a9c1b29e49aaa47f66c73c452d09e4ffe40587bdf080225c017e01841102ceeec0cadb5c8245da442ca51bce761aa0b56f055640be" },
                { "en-CA", "3d5a3a9bbc08b430e08ea2e36cfe83ca8643ee00e73bee83b8b3e6dc46dc5030f4cc26aec6a723e8617d0f26fcacf7b49113fec043b9a130b5b8c232083a402c" },
                { "en-GB", "78969b32d72928606a4284573573b8479e6f1b4a52bc8b8330b5f17e4f7eabc76d5612e9ef4526ed0438097a51932b486b20f7403254a1205ad406efe1e4d0fe" },
                { "en-US", "eaa49449da1fdf61d8d3c4e7571c6bb4d710ad30f921390ff8fbaf96eb8811d42fa894262ba561c0c169b03cdca04b7ef58a182ee8f1f39594e9f31b06394b87" },
                { "eo", "b8b3635adfa4156c33a706065be794f7efaa191c671744c9ce235c2981cf0f61aff26c163b66d7f56e827cd8ae95f2cf5707e8aa1f706922b49980a76677f8cd" },
                { "es-AR", "0c5e0f1631a50488a1f21bb9c68620a15bd2aa79354dcb8cc55658e64e7723d56ebb6b9c182c84d6ab458a56178d3086d9598beb4e19aea31db1a43c615d0613" },
                { "es-CL", "4950f8bc0d00befd771b97003e52629e24f70fd310593b8a3cea22c5651f40e979881105e2408b1f40d52b7d600d0b1cb750aeacbfd679d5c691b4cc3285bad9" },
                { "es-ES", "8bcacaba4e8ee84a802431921b7d68604636d6f8a4c1cebe0803601ac014d13db2aa1d8be115872017208234a40049964ab75d52f016d3524a074cfd5aec46a6" },
                { "es-MX", "0aef7c5feab5802d8b8e7e5502c346aba6245e6e2ee83e6e42f1f8b52af21589103749cc21a3bfc66d0d4d733036c2a552e100a0a46bded6daf282d805835ff4" },
                { "et", "c923654f286c4f648ba72aefe50c43ba9642b6b6a209c8c2605b70a09bbb0ebc88b3488fcec7ec2399d624a26df6072548b3ee10397690d79a3a28c682c8bb62" },
                { "eu", "6eb1d884c37433aee16aaf55ce80ffb6d1e209756b9fea1fc03a8926848764bdeb6095b6a41423beabd48be928d946822fe8e064cf059d458ad7f5edc24521f9" },
                { "fa", "cecce8f5cbae7c183350b4387fb8b6fc566429bc0ffd14baef5a4bf08261eb75cc1dff0e8fa45f3741913cff10ffdff82ab6f6050ff6adabf2cd6118761d5a77" },
                { "ff", "947cbbf87a55efdc9007fd2ab3ede659d70681411017f1db0cc143772108473911c2d310310486cc5639ea0f7537c30cab94dbf4a40541aaa02eda9dc1cb278c" },
                { "fi", "f64cd909b7ac2d08073ae5b77554254a6dcbafd27da8109cecbfa39ae69b2a27f9bf9e77d1b5b43e452230cdd4bfc7c01c6aa77bf7fdee4b455c2a8e1fccb9a8" },
                { "fr", "29448cf062e25f96ba33f6194dc80e7fa143e03ce46448f1606fb6623204096197799e1133b50ee900aa3c735db140618d83db7644407e17168c3f81703ca591" },
                { "fur", "0543c9458c5fe50d20c8ab90ccc9cafd4bf6b379584f49aa3f5585d0f575097f05f9d22f3575ad54cd857198a27645229148bb5c030683d123f887dc31c2f15c" },
                { "fy-NL", "4f208a30034778b35a3afa01d3c5a69979374281a04e31f32390a46e4eb103006d71e6848dd20086a73a4e381b7b0a695fe7c786b6aeece562590b81eb10b25c" },
                { "ga-IE", "e7b305ddb76ea7ac641edd357e94bf02b930310627413890e0232053e459a62cbd4dcc3d57678df76a8995f9f2826c13f1ed9a0b6fdf21b7da6bc38232d3b191" },
                { "gd", "afa9e2bb21a4dbad7a197e6049826e55e82bfe20310c223c96a210294496c1565c03b3f6cff17c4082217e3edad0b1083dc6729abf1b7950b7649f80253bb2be" },
                { "gl", "18bd68eb87b4a711f592352fd64d664a3df19690154a63ddbb9518b3c0a6a8843bba7e7f11ab8b17a0d978de5b5454e72a10d0044ccb2ea72da2cdaaaa0f5bf9" },
                { "gn", "174eb9067ed4ad45d704f0f7eaa3bffd2683e67962c41e9bc83c94879be569c843003c37fcd75160ed94c367ce7973f1ef67c351d34bf7a72d4d4cda9fce157f" },
                { "gu-IN", "71c5dd9725ed3b5a354b3ceab1646824f1c04e43176a879e7453b297b33f4aec7a6152c3557fbba5b38fc4de21d3afd9f4310613917b2d48b67940dd7affe775" },
                { "he", "bb1003073b96c102e1d8cefb51a70527098bf7a6ba6cda6365814d56c0d59f3b8da3a0959926859d2058ebe2c977014398c890462fa8e99a8af4c12e4e7a4ba0" },
                { "hi-IN", "bc8f505c2f97d59131bb1d9746b59affdc98324552effecc948b6e8e105890e68b219a2ce604ed8ca4da8b4ec33e65dbaa3982e32a8606a33cb463834895256d" },
                { "hr", "85c8a49fecb5f55b88a34032457176d15f05744452987975ea2a55ebbe9ff44e1b905b2743696fff7ac1d6052db36385b585950b652500286f15dbdc1661b00f" },
                { "hsb", "f57a09957959d852f050c69bd52b490336f4e451211da911db71f7d2ca2b52fd72ac1ed1fe1ffa185b74fbdf61a46cf38333eb54c518e5991f65036b22dc6cc4" },
                { "hu", "990af4ce850cf89b1393eb656b329276d079ba9f2ee98c7635ce46a92c6c5ee21ae981aa170aec77e8833c50a18337736a6b212a7815608f33b821f2a220fc22" },
                { "hy-AM", "6fb3bef532b0b164cc69652912390942dfb83fe801c879ffa26e1b1b63afffa37858ede35eae54101409df7d8e2265fca17530e366a0a68d0e3d711fd0e16fb0" },
                { "ia", "d84427a4d9266123a8606654e321cf763be6b43d9dd9c753847d17adfaa8143741ab035933a6a64941a80e4a1f22ad1ff06fcef77a9fdd4b6ffbe44522309588" },
                { "id", "ec8b1f93fc3989504f304562f4bd074f5a7b28571e5b59f7ab338635fedec8dcdb13fdec1600a805f2e055cdaab518e56fdd74fde843750f0e80a9c376b068b6" },
                { "is", "ff952c10a3d9d70b5145d152fdf5df5eaf66fb55446d9d6f80032f43002ff69a04c6425057a842834e198944df54e04d51a4daccd3f8edf7e13dab6b0f0c1d83" },
                { "it", "5bb238dcca35f3c2a2ccf1ea1a7327bf6a5821aff9dc85672d8d4b2133cdbd9d47ce4979d1d95653a403c402da208cba0026ba105335136fa21f91089c6c2d74" },
                { "ja", "84f4270cbb0a5edab23504701db7b4519f7f1909f6044b3db340665e43087c76e55810ec9875f889ec1cdc2079888b9820c0918b0a152bc48603504d1be7f9bb" },
                { "ka", "00ffadca0b56bbc861498c150f10af94b322f5ad199e10f0b76ddf089d972f4b74723ad8adff03f5d123fcd78befecbe20fe546f1ad6d392b867a826e8bf483e" },
                { "kab", "3f8dddb50c857e63ee315e2cf8ddfda41501f5f40d5e8efe64192279d7033473c1833a873d11552a0095c12ea9cc49fbe9d8ffe051473a403d9166f1ce5f64e5" },
                { "kk", "97e8d7f4f0b8416feb4b5e0f1725060de175e5ababb7bce1dd325e38271f1e1014c2c330fe35f30e4ec2fa8cb079df482766554b5891a3ef54bc8776863599cc" },
                { "km", "c672c4b07016971f4b21e419cc95571535199e0f6a508357f2401fd8a67af82312f5ddf86c0cf50722275ec2a56b82a77f2bce24f05e6ff9f3bf1305ca9c8acf" },
                { "kn", "a6b09d304ecf84bd51c35d3bfa204962149a055d2be08433635ebf68bcf54502d046cbf65de93b88d07312927f820c0f82550ecca2a727f160fd40e15dc8972c" },
                { "ko", "eb96df9ff7595bc22b2340d61707464237129df9b6c17196a5ed4f46616e9d1ce9729b433d7891d0bc314407cf78ca2db10bfece922dec18d10bfbb428548aff" },
                { "lij", "3fa51f27618bbdce6f547d64a9b105617c3b324274da7cfdba52a8ad112c6d9c55b88363cda1b883e5a2b8f1474afc61712a6d88d28b950a5cca3c48e480f7b7" },
                { "lt", "2e640ebdbaf08fe7c272287aadeb4886c11947b68099eee0a29186558a7d2e77f5c12e5d0328d3489bcb6d2dcdd112332e401d3eb0af7e78849b1a8cdbf49dfb" },
                { "lv", "eb50aa4dbe30d572f5df20bb4d2a8ed52cfcaf9e2db33f2334cd69a4462d7358c4d0ed3e2b6a9ac2854045390e74c2daa47d81fa6a6fb65cd42f8996e9142932" },
                { "mk", "010ebedc3774a5e261628476bc6054d92fdc3976f3f084ba67ef84b25a34dba650d76dd14a7ea4ebb17cda1b8a6715298a921439b2dce667a6fb83a9ca04e97a" },
                { "mr", "7601116281a2fd6acf37d3617e874e26cdf08fe22f05af774c015446b53f5f4df581906511cc1ec6cc43d0f8eb21da442c3e9b28f9cd33ddfff80de0375cd234" },
                { "ms", "82b912f9fc125a14e915d2d90439bd859f4965a7785beb40c0a08252ae66db928a10486f1b51ee35cca0e1f8fcb52c5c789cc29901ca09297056fcf96e4cd629" },
                { "my", "cdd31529bf7320a6f335c914438e9e84b2342946e97e0564f8dd24fda3b19e65917dc29a521c461f40268c4889fc5c793cba7432e266401572754d7a337a2930" },
                { "nb-NO", "626e0fb74bd070a5b616db15e0e1ca916288aa6b2814f6081a985de81161ce7add6c36b5a7ef4c9d36ee9375e70f3696b57dbde000394eddae7d45b216b2d94b" },
                { "ne-NP", "12b30c361997a32f9ed0d78785b17cbdef6cf66233605b6a9817add645b45490de4d48f0317bc6022ccdb6ba21553752412c5b3716d7acaa0b34011138c52bd5" },
                { "nl", "8e3a8fd23acf701413b4b80f6cf44f53887839c91edd383abc3d8546e583e3641e0371ecf24f59ae769c757014c209b6b175644134ae3d7ddd95ce4e1d7a44a6" },
                { "nn-NO", "6fddd292abcb0a046e42789df9ede73e27dc7900dd9b13f895814c3dcf0990e672a28bcebeda92552b5f1a0cf2a4b354ec63894d42fa0e6e1227c52fc4def137" },
                { "oc", "238e6e9240a7508d82ee295bd724997770ce2aaf2ea680014e49d5c52c74f1bd022f059015e15d3c32be20831e5762de1acf1a50ce26f0cd3e57c5bcb436045c" },
                { "pa-IN", "f56654fbc08902843356a59beff3ee3c7fc933b1ecd612e87ef9bca7238dd91714a488a13dc1d39f7cb31b2ddf5c845d65f1aad115b44b515317f94a1345e67a" },
                { "pl", "f82a4b19ef814f9847d82e952910c2acf531f2757902eefdc06844996b623700daaee190ea21025a15711bba6446cad9de40e5b110c5bbc310f8d99421a2154f" },
                { "pt-BR", "89d9fb7cc27e3948fc042e82a3f18574db5cc7db6b29c00e63d2e864b9727c455f9407d18bfe2ece271c96a9e0e8862ba6c38cda1c4a8beed2f053a9a4b5a521" },
                { "pt-PT", "78cf07786bdcbd71da8fbcf02ff5ab95dc4ff9503cd3966b5bb1353ed401de0ec63decf8a7623d8c5e0bfcc356a515b695a14f8faaf67bed3602b0e49cbaac76" },
                { "rm", "9341b333d6aaacbe64347bf45d3f21bba0f76c7eda030569ee355a036fca339e08e04350d59275c3c381364cb0775e13c30151953d038c844fb392b67c5a8c91" },
                { "ro", "8c7f98f9e5ba61f4ca5ab4bc9dc2eaf4a657495dc6d27c8a506d6ee5e0364da2d70c57550eb257faed7a65f0425362af26cc9a0d420acf2e35feeb814978bf9d" },
                { "ru", "2faaa84b04255eece977354db15e09dbafdccfac528d1cdf68552d4122f3594a487c3c8a28ce6ca121d0c530cb0362e8f99dd37a907dd943da319138b769cbe7" },
                { "sc", "1f2c99e659cb62b09ede7d7b7acb2fef19748a498c1d4d2f51bffe395a4dc4013b00a9b645da1e43ea659e2c9fe2553587c1212cdbfcf193777c6ba060f3a482" },
                { "sco", "023f3659b7678f3c2131d1f8a831853292b6e79c7a087d2f20cdf1cc0a1b77583938496a8f2741fca2ffaba169731518dd8bc55614f4a318555f7600b0da3b02" },
                { "si", "d309fa0c7e07b6a46cf46f64b60e5f713fe234c951b937f7e5b0787e985b7eab6569be571669c06477599371db672ed52d80e798e018761da2611795c94da983" },
                { "sk", "ecda06c5a0433de2ef50be7e9d46aa9162abe74954b582de1cd5844bbd887abaa3c3a9f386526616563ce89d377a2e2120fdde8cbff9b4fda4bd3f2a7dd6c9d9" },
                { "sl", "13facb769536085b26072f77adadea5ce3c247cfb516bbb8163a2881ec20cc1876e9afadf19867bc1a8fecc9403c9ccf5fd2fbc68e25f03e73f50a1ce59e1970" },
                { "son", "3cf448b830eb0f9f90adc8fe11b9009589cb08d2a767fea6389fa45fa8fddc35095df0865874d9df7e4638ec9828bfee6fdce7e68325cbbbca77a9071b177fcb" },
                { "sq", "943bc4479d101c603005158182235504cba6f888f7f174756ab2b2fe061ad3c0c2c467df78d194fa59e9e8a736feadf6c39b6c3c53d8e745a9da3639e3e40db7" },
                { "sr", "21a080981e1ff5e430061fefba7ca1ad4392441c48572b5619d5a4c9b49ccf6aa3e8dd55fe297bfe4c6c07186de8e6aa9cbb3279854908762f6f266cc6b46724" },
                { "sv-SE", "37683006dde7eabeae66a0e6c78879a6107df2f3c14c5282560a326510c67689b11cfa03082605609a02a697a2637905340f10d6f4ccb7df152f2bcac1695dba" },
                { "szl", "29516f37ca2f9e40a6ca3b8b038e34ad2df6d42493f6f77dec0f062b8d3fe93c503806023aacc3a769e49841b3f73f3083213dc2a85663ff6777037676712cf0" },
                { "ta", "0539d57c6a18002acbf4aac2f9d98f3cc8c0c55ee03e5d5459482300662ae70dade23774c0d202f091d7c31c1df8f0bc0bf4affaafd4d87cc073b1b896ce7725" },
                { "te", "314574cf0d96e0322c2ecf171e2efd98bd1b28ec326b6a0727367d6825f41bba1355c89920ecfbf51b0be4e7f51713fab303e3f6ee93b2d96155d31d9891e9a7" },
                { "tg", "355a8fa66d18505f79440e727213332c295313590cfa711f07683b41ab369d7d0d81a7a01eb1a982591785d7626f2ab5bd839cb98f174dd27f232a19fa8cd2dc" },
                { "th", "70f24f4db308d71ddb672aa5da3b081e27cec6c5c31e6cf365f34b0a729d4f0946c18c9ebbf2452a9d037cbe564cd1d55cadb3dcc09d8d198bf2d15b2cdcc798" },
                { "tl", "d0dd19d9aa650c33dccf46ef9a1e12636dc956a88f7729defe21a5f2ac6f21f74379be37467e277575c09da629ed8af6bbfc3376dcaae7f7cb094ae6d7c39406" },
                { "tr", "35e32499067f01f816d34c30b539e45f81aa5e092a9d9046d340e815afdee79e492f416fe732d89d255143766b16413879164887b7f43e1d26a6d18a7f304a3b" },
                { "trs", "4e6eb7ec5993eb15bc1e9f1183c72155cf926d6f6de1abf1f710d77a135aad6fbb968c123ffc75c5fde6cce67cd796992ec728ae3461ca765292819045edb778" },
                { "uk", "59973f7cb4182102c129f3dd2ecf4af88aa79dc31f1bebf4801449a6eee3a59b70bc5446619c058799d52ce127373ab249341a42f5fe0054c19b3958993c6565" },
                { "ur", "8889bcd1125254c227ae506f0e8d93ffa330f910d4e5333234fae94e2ad8b2ec37dc8a547240ebea8dfca360e962f75279d8b3fb77455fce717e9111d38e66aa" },
                { "uz", "90c37b42b135fa0ccc2be6f3b59c0892ae8ff5317e2d7d72da92e8c86510a4247fe14cc12d5a23b443f0ea331e539963adbc120f3e75d492896dd093d8d512e4" },
                { "vi", "ddf724f4134c7edb610b0705c50db40bc9b983f4ca5de289edc8333f95577dc92d972d262bcae0088c2ade6f955fc54bf5e1d356dad06c9c8d09d546f27d273b" },
                { "xh", "cde52113b0b02b94a0b310bf829d500fcae0f9abb75d88d6cd53c13174d429b378560f248a51ff0364d9cfad4db09f41a332e196b3da2e39416433abda4996b6" },
                { "zh-CN", "8094ff6f2c9d40cfbcab373ef31d090804990c6d7c569e6555cdd86e8b5187511bf4888f9bf50a9a94e115b8df384bd7c6879092f6797b089f22efe4d1e3b16b" },
                { "zh-TW", "9e2770120c47a9fd4a57e1a834985b9df0922970a61bbe66a9b00fc77a5f9a4b72f3aa26db4d47162e30a829efdbda635c50e2aa94780476bd3c273fa89e4e55" }
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
            var signature = new Signature(publisherX509, certificateExpiration);
            const string knownVersion = "115.8.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
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
            return new string[] { "firefox-esr", "firefox-esr-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
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
                client = null;
                response = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                return matchVersion.Value;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox ESR version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/firefox/releases/45.7.0esr/SHA512SUMS
             * Common lines look like
             * "a59849ff...6761  win32/en-GB/Firefox Setup 45.7.0esr.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "esr/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            // Firefox ESR can be updated, even while it is running, so there
            // is no need to list firefox.exe here.
            return new List<string>();
        }


        /// <summary>
        /// Determines whether or not the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Firefox ESR (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
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
        /// language code for the Firefox ESR version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
