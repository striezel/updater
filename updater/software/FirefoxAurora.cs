/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019  Dirk Stolle

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
using System.Net;
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
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "72.0b3";

        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxAurora(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains<string>(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            //Do not set checksum explicitly, because aurora releases change too often.
            // Instead we try to get them on demand, when needed.
            checksum32Bit = knownChecksums32Bit()[langCode];
            checksum64Bit = knownChecksums64Bit()[langCode];
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/72.0b3/SHA512SUMS
            var result = new Dictionary<string, string>();


            result.Add("ach", "99f16cf709ac75971a882778e595a708f96a30192ea5603885cced188a3a99a511d5d972ee958657669332fe85c99734f750bce00613d8dd14ed323680dd7b14");
            result.Add("af", "a35c7c175f4993e4e3fbd0866cba4dcdbacc6885c78e78c478652c380860388cefe82e2964b5d8aa1db09bcfa089927413beabab0809b553b89717640fc50bcf");
            result.Add("an", "c5b4fb0c01e3689673b1fe73507742d2b155725fcc29fc34cfa7d3c5c8e61684e6fcaf452237468a93d383504dc6b9b3242f4795129bc5988ee8655c844606f3");
            result.Add("ar", "d6255b26544daade75f53031fd08350a079458feb2b85d74c890a594b06bef0f5168d2953ed1d2320ea7234d90f526f514d2ffbacab2225ffc9e0d07da2ffcb8");
            result.Add("ast", "d7d32d44564bca84c7fb67b8b5f0d6d2324e3f20e3041e5b720532aaf4a8d8ced3ca2662c4b8fc5fb840e4f092116111c04987ea47a139e071ba3cc12c96cb99");
            result.Add("az", "46abfa42d2e90771e14d893e36779e44f98687b0878ef4137c1ddb2893d8fa04caba1f28b7d805a620c64e556094a8d0e0071c0350fae3ed644567c3e4b1b311");
            result.Add("be", "ca2caec357c524cd01c25618a815ea3c238b68378df093b2fc8ff997f299f34c856f61457f0b4b998bd3872616dfeda46c3bf2ff1e3ea85f2b4032195b4d26c7");
            result.Add("bg", "814afb6851c40718e164b37d8d8319bc78797dc28b2b877c06ca1e9fb5b9eead8e323352a7937d463b42c80cf06605b5149f83163e8443ddca2209923edb2f75");
            result.Add("bn", "ba9ae206e12bb01720f6883875da2917d1f8bac02d8e4ba4720bcc54dd450cb8204a889ef6bc0894a0763b1486896d8e53fbd0d02fdc839e8cbe626126ee6e1a");
            result.Add("br", "2684dabf54bb51c91d3f8ac9c00bebd0902e4719a09cefe29ed59b119f6969b30109fd6a205e2f468767fe5adee9d9a2a1bcc8c2eb9741a26837d688768b099e");
            result.Add("bs", "fcf6846a9fa4aaafc598473e5c820e68bb44363c642485ae3e6052f37c8abf41fa5305477112fe13036b9013e7a9b24d77f136b69358ed942813decb3d2245ad");
            result.Add("ca", "9a17f24ad7b0884523ac24994836423e38e335ab3eab1c88362506b62714823d14d319f7a77c9e98257d90097de5600413633e517a4a1ec17624876b6829a3e0");
            result.Add("cak", "8ba8460c8583c164064bb618d83c7384d19b5d7cba1561150cfc98437fc13b06bf587e44406eb0cfa279bee9fe17a37464daaa079738af2ec79360355b5b4947");
            result.Add("cs", "32265ccf347903b8f53833020370354fa4f1b13523bbf618bee6c4a7ab980db91838d7473f9fe5914a2147c6f4e1c5063c3e524572a01b1d067d6edeb2524b83");
            result.Add("cy", "438fcc9dc8f166291171047bb9f82a2c2854fc520618043ec92685ff11edc73544c065a6675673f2b56f432c0b4cbf4799dbe2debc5f6efe7c960b9f1d642e9c");
            result.Add("da", "b0c8e924d33b002d0112fe6c1ea34175468e15c2e4adc58b9013b1f7aa5fd11199b0007349f42228448b9886ffcd93ebbd5f2b4f2525e76b699b50c4f7b26816");
            result.Add("de", "f56066dc92f071415eb8508cc235fa47841902060f3e43854c829fba424428c5541f2d73f90d5a1ccff6caddca550ef255184867f7ea2013ed20c8d7186a4f0f");
            result.Add("dsb", "1580562a42d34fd9003664f0a4ec601e4ba8b8b1f90db725a5c7d62be95e26721dee47c41cbb3e484e19f190eff8f8c01260b43fa2d3c1d5e05db82e8ffc5a98");
            result.Add("el", "8c90c5b6dc39f666a6910bbd6431f95e8f45ee12c7fcbfe4911085e3e43df575aad061f3e9c98bba684bdda66d1e61451fe2048832320de502bf192ea3f8bffc");
            result.Add("en-CA", "4a4c7a22a41faec5ee987fabc01702ae8789fea2f8abc553ba9fef45f172e857571b4e394400cb40a3dba2916193932a58c1d3c92768bd1b6fccee22a49fba00");
            result.Add("en-GB", "c85df68ad88cd3d61123f5999875f07027b15d7609f640f045b1ea15f505ea44fdfd5c5637b552dc58fc6a270f17daa0bb6152a50bfd51fc9b5903ac119bf4c1");
            result.Add("en-US", "4dea0afd62532c78f7a83e451c7bb37015664c4ca602d67d2919a73801486a04162fd9a2017824126568b03f55f3dcfe4454d6fe8ef51b06fcef438083252208");
            result.Add("eo", "d7177c441200375c660578711f9f4fbb91dc24f0cb7760737c8b8ca67eb26058307da26641e29a34ed17108b7dfa3e75d51d97dba3a63f23d864aba21409a2a3");
            result.Add("es-AR", "643be19e3bb039447fdd8538a8230705b9e6e078368e052ba80bbf60771257240017b338bdc8af22eeb5a479b8934634b07c4e4298b4b7d59a1babcd6bf84256");
            result.Add("es-CL", "4859695e18385fb4ed483078833fa6207c22c184c5b3ec93525eef80724df5cc148a512f9aef952de58d11d3315a981e07de5b270d4194b9c3a0bfdf64717cf1");
            result.Add("es-ES", "dc50da64669f70c8764ed3658812f946168a4b83ac20559dd2e1c13945f6436957fd18c8b1676fdc26b1f596888b45573a92b8aa2adce75c4b18dbfa2e31c012");
            result.Add("es-MX", "e7010d96ac3d68e39131074c4a28f17a57d86889a4eeedf92ae40d751329042b130b885891c37fbba316980515f068f93dc6c0a2b8b30d80173ab7e2468f0753");
            result.Add("et", "4c054f60bb141096a74386b620ac702bfdce1d075cb2d1c97b7f5403bc44a58c6718364a52e29fce4d6f66e4d27769617fc50645d7025d17a4106080a694512b");
            result.Add("eu", "fe2d48b4537bab50bd02d82582714809b0d560ddce541e1745b0233be8973a40ca0a7c9055a47e819d36dbfa0fb48b8637d3324b8d8c498a0f9f68a4fba45adb");
            result.Add("fa", "bb6c868cebf0bd06c8aff5bc5d5dbbc5c5cf66ab10440e176859099802d9ef8c08a73d1a4893648fa9c7cbd93a1fe0d0d55e860d3177e3e1a86896fbbf5a09a9");
            result.Add("ff", "565740ede0d319f497cb219785d7f185e8e40f0b1ab9adac1bf33a5f1ee16037e8d9f2553ccbecfde8daf2951cce97526aad4193d52dd8baaea83b3e718bd771");
            result.Add("fi", "ec088d7b4c7405fff2bf13dd16409b7f7ed9a538977c5176692fe72166c79e90ec0b66293d74f4204f1cff0cd4bcc6f91bfb0f337659041915f53c4f4ec7cdb7");
            result.Add("fr", "1384304afc0692501b22eb06bc942c3222ab4fa589d685bc2e70744b43e01d2be7f3b80d1c853c4a48726a2d2ac033999f0adcc5f94c4cb1e9444c789ebfe5f0");
            result.Add("fy-NL", "d1d59098d208893e40077bf4d02066411a4f013ce6d5ec15970bb90ad917ec0c5cc848418e9579b507e3e87ed249c67810b9f0e43d62c4b2a3719f73b47a28da");
            result.Add("ga-IE", "72a785d38b6767117773beff46d8e7320e4cd25243e9401e3f92ead23faa4107ac3337b4eb52018303f57cadc84107f05ecc297532c6624609ef10c6808addd8");
            result.Add("gd", "e5236e4fe8cd27e47c0a87c65568a347c674b673811b6c7d03d1083fc1a766f93471b28160b1a3b80dc71434c78e26975f14414883aa5c75ca6033c08c6b59f6");
            result.Add("gl", "05fab39f00eab5da122a201bda3ddf2b00a1f438c61a9631d47c05bb61ca39a09a152744d45b1055a89d1ee46f98eb63ee568f099d4bf7e5836d352ceca56036");
            result.Add("gn", "7b87e22a2fdfea8694ef179ed8dcd13c1a7fab720b3982c5a9558e1e1e23f351bb79adf21f5bd3f6307c192df1544f84ea035a0318971e1d75aee457e47b5293");
            result.Add("gu-IN", "5faba0b1264041d07d8f332aa779b5d0f84594001f78e34bd932ec4385ac45041de189797078e8b1cebf5445a8d5f01569ff9852676115218bcae7612f3b1dfc");
            result.Add("he", "1981b098e958bef00e0c5aa23c32dd92423f324582fb950e6d8cf27fa2405d526238ef27d4f5a1f1d95b2ab99544563315ed5e0aba60589ce9bbf64f78c4b847");
            result.Add("hi-IN", "b807b83a67dc8e3c6169b8ebd97fd3406179e241040d44e98a04865a60f4f625b4eda915ae8ad8a529a231e36b3335af6993ca291e8cb29e04a34add49be610e");
            result.Add("hr", "75d117b63723d655e11713367e09cbaf198c41cdb3c9174ec266fee1a73956abbe0e03c0150c64bff467e120c7e0df8c12230933d6c72b11d817471655492e0e");
            result.Add("hsb", "b486a48d699eb6fb468cf8f1898c200e1d80825e55c10baf1a9cc127839d6fadbba085dbe1715175b015ed7cd35ce4652f252725f09c2133904065965f6ff827");
            result.Add("hu", "e6b453d21745811a96ef2ea7ed7f6da6d66508c772ac0870715a7e511825077ff606eeb3b65cb3582b95a35d14f0ce04e6771e9dd05beabaeddcc35612b1f55a");
            result.Add("hy-AM", "63404ebc29dbe057c64da91aa38cc12cb5b8cd4f4fdb239e96ac2a4fd983e57e4c4713f1ed7114958838298cf4556fd5d14688680e0efaf1a74a467646cacfbe");
            result.Add("ia", "fe134fd205c1dba2cbe98d197b6d2c66f582659f82be0955b38a5a966639afe59e62938b27cf39522a23dff358e195b586149b1d8f07491771991a0689cb2c49");
            result.Add("id", "3b0a9965b86e91b1c0736a037f4db96d3b93a2b86a15a6e7e870d309836dd7085cea6b81eae91825011f08a718432c343f1498da4b4951100a4f14ed8bb6379f");
            result.Add("is", "5f3a5ed85e33171ccfb66b4c0ccfcdf67abbd46ad447fcf70f5c9a8951f400280bc4306f288ceb309e49c49d290738b3285a5c6d89606fe438367b3a99b2c8e9");
            result.Add("it", "130156af51f90f5cee95429ec19db6ca831007339e3f2eb6b03a32d32c828cad7d91b6fee7923dd816bdd6ddd781d214408921e9b5577f75e15a6c039ad0294f");
            result.Add("ja", "67743bb16a65ae54aba8ff691610760def46e40d0052ea5fdb10a513bd06a300a9d7c9aa9fe9d6e2b532414a2dec57da029a10cf23f180342d4d71030df33237");
            result.Add("ka", "2a04e6993626264d57336385699ccbb8f2258580d114a3e800b4e3ab06c49bca50d846c5fb184a5476bced9b83358d8837e9ff1761e2f99b05d3758188f5c875");
            result.Add("kab", "fcff3de3e6af6b0eeab6d6353ca18080ea4d21a6f197e9c3ad981961438c09789f47c9f30a2cac6c7ced3db4650d8ed4c9b5d4f4d31bb975ac6422a1a2de6d9e");
            result.Add("kk", "4025f0ff6f5b7ad8d93e989d721333611c55e85145779b7dbc76e5cc4c7e7ea0d96f6fe982ee6c20ae1cc7b976459a032ae30334a5a2e810a4a21ea0c1447522");
            result.Add("km", "535e6e0e69482ad7040170e075a462dc616fdef0d6c660cd48c9eae7dc36db0d678bfe2efecb2de61abdedfeb36e43dd6204f6c4ea2c459667324afff4704858");
            result.Add("kn", "1e03f8a3dad7f0f9f78994f49f6be4ecb722fcaa7ad6b241aedd91ec9164209df08ded1f931684a28313d3fc73e1bf1b7512668e6dc0a0d85109e532ea086e8c");
            result.Add("ko", "db36f5c840fc8c3845f4207e4e3d32cf717255da13152f89eacd3ff4caa551ef5400946b513bc38c6a270fecc0aaba4660dc6ebd95d9fffd7f8b041780fcde9a");
            result.Add("lij", "5e9df7b69aef525651dfcc29f9bf31256221d54bfdc8cba5b0a56488c41b28466ab6e2d7a21f5e1750c1d5a42692ab950c1b55dad628a3cefc3664bd3184073c");
            result.Add("lt", "5be2506bfcded0b94743cdd5cf36ad343fb4459b7756e779fd951e1327ac11a4942bad0213260fd915154aee684c07b1a0e917dc1fa46fc365c15c711f36f372");
            result.Add("lv", "b4e9eb05d09adac0972855903f75b0447f03e1a9984a1c2c64b67210a38f1aa75e1a8f3ebb6e830f91bae7adba2db74f88576e27a6612212132ba7f43c4bd540");
            result.Add("mk", "9c1a55b610d94e797a0a890599525309aa7fbd622b718736ca43280e4d2a6fd39f8fe8376c24eb93ba37fcefcea2a81cd696561bcded52aa0f8e671efe7b5be5");
            result.Add("mr", "b8cd62d366470c3a87b6931a712a081bce6652f140a9b6ee476259667e8492fa1fb0f3d0f8113448778d50e00e0a1ed56c30a6e4043525b2afb1b60c9960f739");
            result.Add("ms", "47b57f908592d7634d840aafe955a291a2144969aad97e58d2e9df4d3b7d6339539512eeeeea407b5f8eb4cf02d4f4a5b69e07c8777ebb7c7457e10ee4499928");
            result.Add("my", "408631b0c271c12b7dbb08be1c4e406ecfb4dec10e065c761a91c99dfcff100af18acd29fe81528fa865fc0587e5d3ad5bd6036422ff4eef248e382c5bc5eb4f");
            result.Add("nb-NO", "2669a694e29d505a51edf985d766122f60a9393129d3ec8ce70608e0ad84c2f446b0a95e32355727312dabb1f6dcb7d70ac6117106cbf3095d028a396df3ecf1");
            result.Add("ne-NP", "290995688a17a71602be86470a0163707f22e350a3c0b920d07b874d9fd743ae87f6a0c71155a986f1a2e03835c41a63388b2b355ec86de0517e2f334ac7ad12");
            result.Add("nl", "f439be9006ffd6c4fb6a9f28d6515b2b04ae391b034d133c7ecf9831397249e368909caff6477dafbb6bd7bfd9a935adb744398ca624dbf0e3da920790f59187");
            result.Add("nn-NO", "bb30bc0042d5dea27b58edce7c1b4d0a131c3023d4e53a176158109d35c116d62b0ecd4772c853e00d5a965c94347c1c85b31994fcdb66d4d27c59eb9739fb3d");
            result.Add("oc", "11e91d831659d72e3d2ad3f1d470c6a9e92cc86afbd35049621130f6ea70aecdb509f186fb0839a4243c92381abebd57ddd130d87d6e5bd08910f3621b0e01f3");
            result.Add("pa-IN", "a6ed6039b83b53135e7a959b08f80a2d458631c7e3a34124201f349691d01983ab7688551e2471a0304d32d5ad29bce81b92ad0fbe2819e6988c6f46b75379ef");
            result.Add("pl", "14871abff78ec1b65086fa0a7a6361401684e3330bc5fd19303354732a6c8b764069fc8ef1e8aac8543c6e0040f090c081e1e85aaedd49f50882b2ca90718b9c");
            result.Add("pt-BR", "2359b822b112491277226025a46cc4519ada7a87c3d9b1ccb9f45a5e7835a33019277aa32c73fac7ddb4a9babd601413c413ce6b256405f2cc9240f1e6b1e506");
            result.Add("pt-PT", "d48ffc990a623866f9a7ce6b30a27473643029941488b10f894bb11cc1d631f7ceffbed57505d286030d518bc7afa0e16a547c100cc907e23d1e5867b14c6ac7");
            result.Add("rm", "e876af2efe54d488e828512bb1beabd2a636ea53f2f98e8fa8aa560376c596f1db13c5e36ffad3ee1cd4c6627d565e234f7590cff7af91bd1f047980442fd448");
            result.Add("ro", "2aca788653c195851c985a62960a28f0898d2dd26ee6a9fad6c8e50b3850de3e0b965b18dc479a9e662500e5d0c8172ad2d2a2fae2f41dc54d1505d1983bb505");
            result.Add("ru", "8d4fa24c0e53b38aeab6233b25656c8c0dca40aa3f9ec8c6310bb59c0d2b7f5cbab90149b1f191d31785761060eb4c836cafe25cb9d98648836d3f2acbdc05f5");
            result.Add("si", "2c51342953015263715eced54d5937e06a955e70a75045ba889dd12556755594ea151d10d6785de61dabcdda939bb8336db033271e1b820e04e3db8e680edb51");
            result.Add("sk", "d5e03862efea58aec72800cfd42938398ad1abe986e856abedb58f495930920921c179c965bf0e0ea9f21b5a3d9cb4ca11509da37f2e2cb1fb14c91dfb6478af");
            result.Add("sl", "2bf24ee73abdbdf75b019313ec09951cb4d11af23509f9ef3b77050f0ab1a1eca74064a1b902f7adbfdecc8f4180bfd42c53d155686dae387702b89c9979df44");
            result.Add("son", "eabd1a2c53583f410a84a3aa0413ad3b9b11a58a647eea411dfd7d81cdfe2b4307d6242752028a4cd5db18c705960f68b861658a3faba9a8ad79443808bc944f");
            result.Add("sq", "b44b0a5db315a0860a936c2d6c575ba9353ecb9be7cbc3e7d9696fce30b4381b0489453ff6bba27ba540df2f8176c6da7b31d9e02a7be19fb246252c7a3407ba");
            result.Add("sr", "919e8b820c1a2e75fe000f56e432f48c4e8c7612d90a5af7b7463fae166be0f81fa9e06da08893b93e60d3e31cde15e3db3fa564fd01e04bcc7b405077828344");
            result.Add("sv-SE", "e35543b5a6645e7dc5ef965c0179ca3e361c6e11283fb2c305770f398e8ab8f66feb321819e9095dc03375bb2d914ba50198a5f0e9e0e33ed5eb467220bce578");
            result.Add("ta", "0a8413b0eae4eab3e032bdf78ae0243a3d7f91203793f7e152b6a7e3c6b0642d752ac985571295360d242bdeec7f282b6ae7ef322138208c705a3e484ba0e55b");
            result.Add("te", "43fe8adce878637d85b99cccb7e93a746d3a794c0a3eb48ffd6295d09ccd8af28f539d0fc384c7c0c5257eb4df433e3e90d6a3ab19d16317b8d0e528635de72a");
            result.Add("th", "72ad0e92fea379a78095da7633a804a55037aa4fa25d39a3e7d86beddbe1f5786a3fa3e763f60ed3a163febf2492e423ffc5cc59f5e2d0ac5f32c0c330179112");
            result.Add("tl", "dd431ce47da54d0825a8f510d7e7742a500ed5fe1c403122e49c756e2755caead80e4209363742204e4949d4e9c177a4d140284703687238f465fa730b0bad78");
            result.Add("tr", "9e56cb8dd7f33d6039a7d56b2217250caebc9f1fa288caf73d982ba87fcc2e6367f49bcfb039e1be8f4fa14d656a21a3a254831f8e77f9b0345fffa8242843bf");
            result.Add("trs", "8b1ab3f692cda8dba0630fe084b8e6ebc95579824947b950a7067e10ea56362fd9b12572da2bc80581a57253958fee0654292fa4568cf74965de09fff0c3e704");
            result.Add("uk", "fb3f6f53eb70b271305aad5ea75e65b190945b65857dbc88c8fbd8c5102f0da4bb6070ea6fbf8df9247cad80e8dc7bdf5d7c9ba3c17ef97476b483d0e1006f82");
            result.Add("ur", "d8c0f95b2532d7fcf23086fc5131bd0d5b68180a8fbfa0a4f95c7f07780f1b3a016af9660b0d8f42ca2a6ba9fa68647be47c2982687af26e1c4ba81021d4dcdc");
            result.Add("uz", "e250ed4a5db3ab17cb40b182b33f285d84148a0cce4e33ec810a4f086578cae3f77b69288e57072c74accd7237cc6ccf9c431a73f2b53a2e5ea72e7e3e7705cc");
            result.Add("vi", "f675d92d3fccb02962b8db5b6e3424a5af312d1756611d278163a815829d855a8ac9d7f4ba9d07fcbfa3ef48521259996dc8cbf85f9ccfdbcff69c2093e65c8d");
            result.Add("xh", "310916eaca104055ef5310396b3f05bdd3c9dde64ded654a9359e7ca8c8d10a165a5b16143149e3997e09a443564e3009146d1f7253008d5f6c9982ce463a66f");
            result.Add("zh-CN", "5cce46ac1b734a49664ddb44092f5ab66396f57ec781f6a28a5b8672337481a16452c3eaa24a88ef40bd58341e988ef3e1e6d43ab1ccffb9cbf70a07e948f4ba");
            result.Add("zh-TW", "56be30e10002d56913a2d05db35176e20a55cd66e4e3fd10e1c96886d3619fe9f816069e434d1fb28c44969ba54b557a46d93208fbf2b65c2142058ccc4392cf");

            return result;
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/72.0b3/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "5e56096317bdc6d48aa6d95e7c2a2e593fb5262ede9dfa779d122d9fdcfa2ac785c91418189c925d71a4a62e8d8fa16d31030b28c13b6fcba84944dde6eb4a92");
            result.Add("af", "558013c5a2f4a775b029702e3e62b094418296299cca65416822b90a5a20a3466c432462928dff60899995225d285ba85e984a0cec042cb96aee5491b3e74db0");
            result.Add("an", "49b94db69121a33bdd963c25067ebfb17d185fc851f192cf0a8ed45a523e28c1a4301bbe73a5165106fe6080144bb5ca2f875c79755b761755b28c15453a43ed");
            result.Add("ar", "d117a314220f0ee386f28bd2ba315f1218094eb54feb6d36e900579d44fe3df37bc45879cd76baba1c7439f5bd9714ae397ace6eae9c8f6585d4a7a8447ec293");
            result.Add("ast", "a820db1f2aa1e6932f0ca3ab3c5f9cf1c92c8749542aac9b1347f2c3517d2b86917461cb118b648fa4dbf426433b579327b5f0b735c67fbae2fca53d52950e46");
            result.Add("az", "1f6901165835c3264999e48b77f08bf9eab1beb74705f7dfd5ebd399f0aa23d97ca798d3757e2a31b931484500a42222f23223fe3a54b3c6d0d46a2f400f0985");
            result.Add("be", "2ad98afbbcd0d26cbadc2ff982860ee39daaf0ef42f55b5d9e984e605bde71ac001f10fdecab9a550a970a4ce7a633570ddff494667a59010154a4493fd29ddc");
            result.Add("bg", "4a7e60152e8e03d49bed645634cf20a0a2430a9b1ba4e8a93d56b82d77d0149f88a7cda826d0573e67828dc7b7121945a1b06f887f27f2d1f514e085d7fa32bf");
            result.Add("bn", "0162121bc649c0222ccdbc6760f9abfda1e5ae347c105d6a011f0e6bedcb79ff81d724bfeb5746bcbfb75ef26a75665cb3e03a113cda7b95bc6a985be91ccb12");
            result.Add("br", "d04d349cf961516acd150f0a918f41336744a5fa86e04abfcc6a96e9a7f2104f3632b3ab989712caa5d21acb513498a7480071cea5cf3a0198369e6e941931dd");
            result.Add("bs", "217fd5ca6e385a4a3ff2e776aba01ed2f03136d9f46bd138b8caaf50cd65f01bd7e873b18770cac123bfaa141d906371d9bef1b8425f60cf2a86355e5f5cc101");
            result.Add("ca", "b1b9e858540d2370f348f28ede82d8074b05514d8c96dd6e5c15fe6380ecc14e5c2d09eab134503b9cb7bc62741e4bda5831d54a200cbf8abfb5165740376394");
            result.Add("cak", "d1d7cd1c08a935f18cf0bbb181eb024a158d1b7eb5a839cd64ead36364a1427dd3640385950f1591a4079062c5b925985f3494ae296a90dbcc902fd5faddedfe");
            result.Add("cs", "73d6bc8838e24d7f0bdbc2002cc67f6f1a06b8bf4cbf7a7a92ccdc96b5598a428b62da5b5fd9885ef64c3143a8d346bd48a84d8d728ecc2e94868c176d3a52e8");
            result.Add("cy", "6685182774cf1b32e512e204f6cc2a263c215a900d4c4e873defd01fc2d23805845cec7f44a5467580d76e432d6dd3de49227375e8582372333cdb279bc3199d");
            result.Add("da", "2a57a23d94e9698df2504cc799f01f1077324f7fcc9958ad8271f9d29b6e4efdb3b440d3d0b8bec975693342e75056c882d9743200a13ee4eb4d9198e1d1bb8b");
            result.Add("de", "b615e3b0fd1d4a78d5751e903bdeee3b2564ca3933ffa8fd29aaf4e7a3287a63044885cd7df08efe4be26a38649332bfe5f16e5a0d2e7f0dea9a1441095789e9");
            result.Add("dsb", "7ea223a42c3a5ce3285e6b042346281c0e092c71354982bb0294f91fc3f54f6cfa0a46e36d46bcca8f4a8752cda40cc8fed3a6f55894f6210c6461249309e867");
            result.Add("el", "60b0bc37dfda4224df57a5b7edeffe917391700177c8ccd07725c860317843ea9e5991d797ec8b5a0d3dcfbf168bf0ad0353ac09db54f4f5f9d881200b26c43f");
            result.Add("en-CA", "a3a72157d27da6380061fbb4a87e45d08a94521080b153537ff2dc26a2e0133874f771a17c7e435a8aacaed8924212de9bb970c9e4bc20987449a6dd03bde850");
            result.Add("en-GB", "e7c623e0ef8a609905c237c4096474c140fbf55424480b0ee330780454919f3b199eb4775c2fa26d830eb423bcd42eda762ac2534e6622b811f95fcc14e630ae");
            result.Add("en-US", "bbd19ea8d6118508b8c6743dffc7006ec434d2a2828006e4fb3425fc5ba4b3cb2e3fcf6a0cb3a9648defabdba9853fafa30b142cfb1017ad7b2c07695ddae1ab");
            result.Add("eo", "3e696b0177515df9d7fd98b72d26356be5e5d584f8e033ef0f4a180ebb218307bd01e9c2882a9bdfe5ee5bd025b1d2d0df14ded1f391a9aeecba69c71907194c");
            result.Add("es-AR", "3745b2ec6e66ee2fdd7229afb463d0df4b4227c98aae7c5d2580903a88b162f90b6b40ac8e7c2cf68da421689ee27d037b82ce4e7ab32c8f7d82018fde1a3541");
            result.Add("es-CL", "0b5048ba35c7f3223bc6096e59eea175efb143159bb7452eb5736e69671decc07725aa964448756bdd064afff2e19e15e5220842361d4d25ba9870131224527c");
            result.Add("es-ES", "cb1836e8b01c6a0e6ce8b7828065091274109f5e0007db13f3b644971eff41bd4200a61383b8c975238566b6a401dc501e92b6bbfe5f2bff49c10fddc63c3a4f");
            result.Add("es-MX", "c4438c1d9329f689a77f13d089f0aa4ae81170efe77a90b53b1f361fd1cf0ad8d9ede16f93a8787ed13b2a947d93b98c9d37993645776ec9d1c39231e6e892ba");
            result.Add("et", "586175aa88e81ac37a2c3e1c72352b2a18808ebbb70af1f5bc9ec1826453cd52c617297f097cf2ade3b7cd542f5287defadef52590bad025b25a2692d14fda4c");
            result.Add("eu", "76acd96bcd6eff048d4aa69f58915b81935b94bb223b0421de6e6e233669aee9f1116159641796f97f006dc109a26ee513bc22795d27e08024f46aa4e0dfffbb");
            result.Add("fa", "9969870230c198630a574a36856b8bd8aac1f8d1b5bef24a18ae1a9e182de00ea2bf4f672f97d96b0778893645fc272d99b4a72fcf8028c086715f38303a9f8c");
            result.Add("ff", "bd279efe55cd05538afedca5f3b6a47c2946ba632964607e166e51c9de5b145bca0db2e6ed745e888d76672605c179781af96d47bb0c27e2e9148d7a5bb3d954");
            result.Add("fi", "3e20c1be1c2415e31957be83d413abc63edc83ce8194a14ba5a01b0a38d007ca2745e589c590912691758006a16134be9f30b807eaaecf24d77a7bf8e142a1e1");
            result.Add("fr", "3d9afad12f43bfa33d08385c43c46d18dfabe06727224c53da308e3def3b93f4025ad2f7c8d609f943a66f91f32d6f0d8ee2747cb218dadc794b5f55f89a235f");
            result.Add("fy-NL", "96620a2a7a30fd6072b4f4e2eca36f51d1f03f9c973e40282cca65db00aef63f929aa27660df5eef3108814ec2b7120a480ce89798df311a6080c4fbe560c939");
            result.Add("ga-IE", "b06bfe8bda54a023893da09dd4fcf714d34925485c4ef0fcdf2c32fde02f3cc1b069100ee186070570631cfcd4542ba2f721d8368a97ced28e825700c03b1638");
            result.Add("gd", "77bb4deec3c7b7447fa200b1a6350c6399532e755a16a76922b3bc666402b17b534e6ec6bead217631484ada14a86c99a1307c4c85c56f1c7e8becadcbc95107");
            result.Add("gl", "d86219b82ebeaf93fc03b179155ad7844a45d5a9f4eed5ea1b0511f723f731c72d9288d292ee2ad8e65d66df3a69d24442094672d474c4472bd1bd6d460ff652");
            result.Add("gn", "b525b8250cfcb719d07f2f2a37072c072453815e6bb0e926c01350c431ba8615ef512a753b7abc869895719ebb70b948d6c2277009c1a2bec99c5adea0db28e3");
            result.Add("gu-IN", "1f8766e516ff63a5b819d0f96bde752b03cfc2ff2ec639dcb73668dafd4d1d31738b1484c343a40a18c5dc6c984af3f5c9ef3992f7d8a60cc71fa057f6f2ba93");
            result.Add("he", "0697343f7fd1db412f7d6b3c5fa669905c5f9d8c88513d6771d186b9b7b96c45d932e8efa7160658fef360c557edf857d1e9762f552928c51290ffc92f5dcaa1");
            result.Add("hi-IN", "ba1d13873895cfb292376cefe408b98ab2529cc724c6a811b9b5a1152b13ffa49d572e68a2b96d27abf9bef5d329c83f52b7289cc2d14368bf21092012b19e51");
            result.Add("hr", "ff65cebffbddfe969a4fde8d747603c14da659eb2dc87bdf955d2f67fa0196d48a74e8dce7f37cfc32c037f6aab9e53c5aa5e1427bf83a2f94f4fe1541652593");
            result.Add("hsb", "705445235974979c36650aac1892d2297ce3fa59ed261feab47d67160292a2c4f7e2601de3c9472ba6047673774d535be6fcf7689edf9809ec311aa1d7f389ed");
            result.Add("hu", "a077297b9ac0470e3717d526f27eab1cb2f314cf2c3b5896a5b7c362acd72236608a43d62ddda6d031aa60fe0ac9549bf131489f854131eb9d5f4a833d6482c9");
            result.Add("hy-AM", "36dec8cc2bf90a1d334c3d080448c66674ca362ddd838d902f76a82f4a018cc3ef97126ce8312fe1117dccf1bcc4a85dacb38072447878f274eafc2799404f84");
            result.Add("ia", "6396f5b7d94734bc03b7322a4cf4cecf379b65f7564592bd315cb341ea732b36fa4432932bfbf1cadcf401a2d814998b74855098a52e10e5d836208a220facd3");
            result.Add("id", "122a83b089f845ab764b22cb731ccb5fbdd1a60abc8565d88a1f92cdda9d8a6eb9c63bd6c8fd77c73bf8e0a52ce6e708dfcdb1b8bcce2f281a5cf0e9574cf421");
            result.Add("is", "03cfc4b240bdd9709b5a9cc3a7f9875e4f15ec6237c323a561ed0ab9df0f0dfb5b9b0374258b90bb4489c990ddbd8830dd05782b292f250cbcef21561ac7275b");
            result.Add("it", "aaf583f50b4bd59895f7bb7be544a09c540786c38f4d0887e722427849f2e309e53f2e422025c47953c51f4f97226a635b0bc6c687b4262a7989348bfc3cd83a");
            result.Add("ja", "3a711835ea60e89f126203b59097b150640a1cebdde72375a72ff400fb630601d260c976702ed3b0c8083de3cb099b9d575a00a7116163f410895e5dab08e841");
            result.Add("ka", "16086c6536afe67607efbf46c873bbb223408d23f3e966854517f3b352c1ef71ba2c6c5510193a07ecc30c94ade27635ca310fc89859ff9f2c9a31994d1b9db8");
            result.Add("kab", "fa690c4a6908c988dc8d1e7efedaff68a68ef403cc5f5d876713a5bd6ff939a2ada738d5333b35f60da13e5f3353562a0559bd61e83837e4ffcad40f68bcf36f");
            result.Add("kk", "1262af7a0f9c24f44ddc4f45a5eac78040d39c259e5fb7dbf2330d5caa4822f08616698e29c6f078a3f2267898d0e261467d2f5ab9544ae5d21cf759c0523532");
            result.Add("km", "5265fa00285d12e4d085b3d16b7b6ce0f3af2c4750b24d3d872b12d15b48803c3178ea0de25123411d62be502b982a39629e860e37c235d7c8320a77d4e53392");
            result.Add("kn", "b7aa307873cf3f68516ecff7111075e2b207e3d15f453ba893e5bddddd1f175a7726e306d50be66cdd3ce458c2673c026fd43fe2c76dbfebac3ae26892d8bb8b");
            result.Add("ko", "391295aac23a1db48a9c1ef8ba543b10c376c08dabfc1495e934123056876ac1f3955ea7546327898edbeba9523e24067e53885dcc80f7257590b22872f54e2b");
            result.Add("lij", "6cbaf7f76986949b4176ea5f9bfa4db86e32cb4d1d227604a15710823df30e1a7c123bdd78cf7b4473a68e9a1182398ed799c84c3de21b6e1544c80857a643a6");
            result.Add("lt", "e8de8ecb896eca756d528ad92c7fd5b06c0092cdccf42f183fbec291fcbdc9df0c08a5ab6759638e6961119e197125ea8e9d293de7e84ec5a7a61452ce821444");
            result.Add("lv", "ef086b205b8cd7b72d398ec4d474112fb94436fe837cef8949d57085fc07f6e96fbabacec7b6063202d4c9234ae09d98a512b35a0cea4ce1823a531894ba56d2");
            result.Add("mk", "f1a73a33332ebab65759dc9c007eee645f9da620129d1c06aae91685355ef3a44954d465047a9d2b1a6acce5b3e67a8a1a393fa1df1b5d42f05ac9832ffe7951");
            result.Add("mr", "cf14cabf598f8d4936c07f2889785a78cb1bf0fb5d098f10272da16e282f44565b1c35f390fa2d148abb926a1138bdb58b2c989fefcf435518593c4c480608ae");
            result.Add("ms", "fd2f075fed41752da7f4bd38c35b59909165c9d602017652c9da2dff3a213b6b58ab436f6fa06f637dcd603357324c1c1042f1821ca75a4ebb363f7935633e43");
            result.Add("my", "b700223ba35fa02687e9be83725473a70f9d5b2eaacd8e26dbd2ffed3e7559fd8b590a04694e993870ec4549eec869311ae1b0eb7e4ce35ef86c6c3b545ff428");
            result.Add("nb-NO", "7e5dd5de95f9f7fe737ab5e90992da9df2f93124db82b1dd8d7f0c7dc95d775489df1f49e1dc3ba40c1ff3900c6dddffd63ec941b408eafafd92d3169b28fa10");
            result.Add("ne-NP", "520a5d3a764ca855494314d083bfa43205f8764d8ae244b789e5f3439fd19d09da84f1b0165aed7930df64f6195609ab4bc74093f2e580cd05495e785cbef074");
            result.Add("nl", "e296507e928920cec745e17a6d64779d2bd98bde422d3a2b05aa0af887d9334e635127f4b70a5ca27047714d4c13c6c53967b4eed9c4e8fa3807decaef14066e");
            result.Add("nn-NO", "38c013b0cdb8afa05b5ad39a5bd7479f574d33ac7fca8f9b7a0cf141b8ba36c8df6069785696756224b460cbd94a7ae18c8f43df1d7a3633dde06fa910494640");
            result.Add("oc", "99dcda9d2d2e96a5483a93534a92ce85838e3e7f9629efe28b8491c67e8117195cedd81333326e3a11ebc922a4c1238d29659ca4646c56e5e9d8bd975901adbf");
            result.Add("pa-IN", "5cf84d839e8bb0c8aee5febe84ffd38c1f734358de6f05b81ab8348744d161d66a0bb188b69c2023aaab2758b254e649cb24ecb05c28b751ba1d183e566e1ce8");
            result.Add("pl", "fa214bbf0c90527e8c3345e80f9498cc22eba83654a2a1036b12f70f211a3a70e372b40a4aae080aa0008b6018a72da4efb25d516b9572a19b48523a4bd308b7");
            result.Add("pt-BR", "ba1fb89e1a12d70c039bbddd338f10ec8abf18b5e5b309d5388bc1fdb16667a63be037151bb06662777b915f503c4cd9a1914569f3942792d872fb616e6e39a0");
            result.Add("pt-PT", "ac95a1dd65cda38b5d87180080d58213aa30a636afe65ebac1c9f112c7a0e12fd02d56116d3bfbf6a9a61daeb8f8b714b3dcbf1d8c9616f509286dbec4ef0996");
            result.Add("rm", "c6962aeb947eac3e8cca8889a3e8c4e703b5312b2010a191fdfb8132491cfc01dc0ecc9f97bae397dc921a25f040e5431d1bea30a0e6f057fd6d99f4b5f7d90f");
            result.Add("ro", "f5eee72aa577f2e7f88fd07b9df7da441b7782f819fa2958bdeac2e5b33496de8456695d42ebfea335bf80354134342fd0f0bdf28d142d6634534c5db7249405");
            result.Add("ru", "4071e63c1b974b7ca2cb6ec34adf53edb1535267aa943aa25fcff59d64a2c4034d078150a1094d98667a4d0913ad97ff533b89a244f8bbe094bee1f0d02eb639");
            result.Add("si", "761917e0605c8e6a764db1e239bb4b01a6cad5f8290b3a464cffc9366eae1817987a670bcc9eab20b1472f9c4ebf79fde06e87b40bedd130aa8ef34ec897695a");
            result.Add("sk", "741b5b7e9f990a671eb0ba76a4cb8f9a7f5af094ad3ad417a086b0d4fc12d57affc84c360af95caa4e427464ddcf496047848ba722145d8b872e5761370eb78a");
            result.Add("sl", "b3c444f317b97aadb271af4b1c4fab255951b99539840b6b0ea0df4bc8a2261e97333c1b5b6596a055678547c25753d8fc4e72f90cba9c47cb9a457b4e4983c4");
            result.Add("son", "d9cd2044bb174f1bba13d5bc9004bbc5978fc129f9c7507ccb855deb157fcc973cb95443f9ea698a36e43aab695e5cee1912944226b5d1b17b8e972644c693fe");
            result.Add("sq", "70827beec93d2b853ff175a08cbed8093c8149cb1a026dff40c090ccddd6a75482d697ff22ee152d3113e439200e1067663491fb202be56e4e1d15fa8852d381");
            result.Add("sr", "91008a5e3522714b70a63af73107ad0e1199875bb957b78178c6c0cc50543a11101c166aeb6df730849029040319f7b5d9506fd629e557f33c82205d7a79f4e7");
            result.Add("sv-SE", "613603b39df3ff9101a34a0e1447c6583c43b8049f99fb8832413142da4b8ee3ea8ccbbfe6c4eab507ea4f3d52fb041fce7f0758555a5c70eb052d4e8af051c3");
            result.Add("ta", "4dfe8b2d3aff1029b1ead8ae8d93a8ea5063cec1ac357d97e58424213bab7d5128ed573f5cead789ef63358cce88baa55aeb602edfc6113c529d946e3dba711d");
            result.Add("te", "299545d12f8ef43582c32c970c2821aa4aff7581fe915d9e95536044a997f366628b440eb6b5edb5372669577107894c3535ac157cc283b019a2dc567bf4e330");
            result.Add("th", "56feb860128cd2fb7f1752d2220d9a8b4491867114b9ba39ce21ca4a61ced90e8f5a8528291595981be7bc235723af72787c145f6968e208e7593155c70485a3");
            result.Add("tl", "93c7fa7cb22b6b517cfe4d463e85ba31c8e54c455a381cea498f544d8fae6d27b374550eea4763505727103931aa3fd786e943f51349711e7548cebf68eafc13");
            result.Add("tr", "179ba1dfffc201bfe64194b13895a08310bc7bcfeba87f99c4d1cd5a4dfa28c12816a07cdba786b0a32b15935c27eeaf004410b58ca4a8de5b42a2f6651760e9");
            result.Add("trs", "cfb96921ecb09cc674b2ba6ab079dba056819998628c6c1dd97f4a4699929e7e11e91cc8b594803c38918974781ca6cfd1e07cc2e6b40e948566862fbbc625eb");
            result.Add("uk", "d9c84868f00ab3a91c27a201e09805e00c1cc5ee33d611c7fd63abef10547d3b475dcbef979f59faa910814ebb94af3ada4a4dbd8703de0ec92457aaccfcb315");
            result.Add("ur", "a3800254b7071e3ef31dd6853dc67b3643030dfff3f8626f4f065576ebfa828c24260251c6ed2b9d534f0626b3d5ecafd05fbba11bbeb3a0eed739bacca5f6e3");
            result.Add("uz", "5bcdc94f6bbe835599c41c2cb08a12e8bd6c9a568b50f546926aabfe5448122b4bf6a473f097ca5b8fb94f913d1a24df88eb2d0f0e2565162806bc554f10c018");
            result.Add("vi", "f4b13719a65d5d690bca907c3e45fd684ee533b672d983a10be6c4a86b60aa388b2a6bce6c2c38f7a25854c67f703857f292fed6b80e6737c2672c0e43ea005b");
            result.Add("xh", "02aea730e7fa76741e3515a33cb9979ad7088db9486840f9f577c50a8a82b152347552ca519ddc7a434923df22ff53efe87ee56900e69e842ec8cb7ead56263f");
            result.Add("zh-CN", "2f8e756fa91d4449929f2dab5d96a2dd725ebac459f0b918991fd3d6d374aa9dc6fa4867f3ed498b627cd9993d9d751e78f50c773bab4e5e6b30ddf0cf5ee778");
            result.Add("zh-TW", "06833f341ccdb3bc4dd8347f5272ef8ed3d70edea40a945dd40f6afe0fd9492db44989619da182e07f9d9b60b32ea5e4afcddc0f6e3fd68ba1bd0ab39c3266ef");

            return result;
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
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition [0-9]{2}\\.[0-9]([a-z][0-9])? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition [0-9]{2}\\.[0-9]([a-z][0-9])? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    null,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    null,
                    "-ms -ma")
                    );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "firefox-aurora", "firefox-aurora-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox Developer Edition.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            List<QuartetAurora> versions = new List<QuartetAurora>();
            Regex regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
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
                return versions[versions.Count - 1].full();
            }
            else
                return null;
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit an 64 bit (in that order), if successfull.
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
            string sha512SumsContent = null;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                using (var client = new WebClient())
                {
                    try
                    {
                        sha512SumsContent = client.DownloadString(url);
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
                    client.Dispose();
                } // using
            } // else
            if (newerVersion == currentVersion)
            {
                if (cs64 == null || cs32 == null)
                {
                    fillChecksumDictionaries();
                }
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return new string[2] { cs32[languageCode], cs64[languageCode] };
                }
            }
            var sums = new List<string>();
            foreach (var bits in new string[] { "32", "64" })
            {
                // look for line with the correct data
                Regex reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value.Substring(0, 128));
            } // foreach
            // return list as array
            return sums.ToArray();
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32 bit
                    Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value.Substring(0, 128));
                    } //for
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    //look for line with the correct language code and version for 64 bit
                    Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value.Substring(0, 128));
                    } //for
                }
            }
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
            logger.Debug("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
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
        /// the application cannot be update while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>();
        }


        /// <summary>
        /// language code for the Firefox Developer Edition version
        /// </summary>
        private string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private string checksum64Bit;


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32 bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64 bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
