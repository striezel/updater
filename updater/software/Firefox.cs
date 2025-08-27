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
            // https://ftp.mozilla.org/pub/firefox/releases/142.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "696a40648df6cd208a3347a283012a0450b4b2dc90ceaa0920558865178a6439ba5101420caf08abfaa7976b86e7a97868a1f4d41337dbc108c07ce3dea864ca" },
                { "af", "ee6010bb104b7c14a4df32790c55ce700cc7a0131f9881a8711d829bdb76325f58e2136e37151a4d6328893ee879a77fee62a65fbdeac48305e7cb53597381a8" },
                { "an", "3342ece19d3fd0433084cc656e823c4e4cc49eaabec8521af8a9802c3e1c4a8b6356e8727dbed98b7d9077210d4c88192a70e25c595ed4666a46f3945db3787a" },
                { "ar", "caaff55956da982890f7b7b0df007bc6e0482e813f60a61617a0b41d6d1492c7620847bca105fff6a21741d8cbf71611a4a06edea0d916994afa32531e133e15" },
                { "ast", "84bd4baa1d0ba3a36f5b4f0c9c97d3a549d5b5c2bbb8865a238e2f94bd346831a85df08fcd07fff35f8ba7022d2c2fe28a2c3b16ebcd82d604d5aeae9013ccbd" },
                { "az", "70d07fd4941aabbd79a79610e5668828b327e620529621e69b1f9f70962bea9e7945eefbe07d5529a96e14788b89ba67aad0d7d60d8100a9ad6bafaf428ccb22" },
                { "be", "f0a3c24541ea8232ed2729bfb258f128432263434fd2e37acf926c67268c6710b1fb4c82867fcebeaba19da1e7a2b2c85300f6a82debf59d0e3f99c552a57606" },
                { "bg", "7129f557a4de0533178c23a23f0d51756e82440dca82a8d9d3d659757429603925fa2f20f698ac85f8b615868d94a3509a6ee73555db61b459be445baa2027ac" },
                { "bn", "d6f41b35a8fc5e5f740766368cfbda685d3950bfd344ba2424b55441bf8ef52bdf403ebdc6e5f98edadfe506cd5a0e29cb3c665358c70a352ea6e2b908df9bac" },
                { "br", "28e6d1379e65b7a97d1db861540216b95d70b94e94c0ebeb78ce49743f9312dde8dd7ac81476c59a5c1f5e112e483a34698333a44225c31a043b34be94d33c9f" },
                { "bs", "6ed69251347c04bfe9222bf275fee2d40f2b5abcb96f22e1e06bc78b0ea9c9c643cc22a915a80aee1839e8d570491008a342b0c35402082c3cfe6bec7bb4cf09" },
                { "ca", "f5b242ec0c29a8a2666319f46ac8c4551320476a727c5cc5d93e9e63e5256c65dea19d3efd8296e05eecb71bb2c3054184a689ce2a485211f2d458317ae70975" },
                { "cak", "ccfbd3385ce7ef81db1153eacc3023fa023c76981cc0c27218e06598d9a254b6c98e1f41e77ab5fda21ac04b4e19ebd1876771f077e836c494adebee1594be67" },
                { "cs", "e1bfb3def65ac7029faddf864f60084e4287ae91e00e10516e2b5faf956741f443b865805b9ac85701bb4c3cc6f20fa5e800f707edd64b62495c9b1cc661625a" },
                { "cy", "d6d335085634f46a7ec7c17105e4cc8022983899c231ba1ebbb199242f0d4b234681fa262f89cb9a2e46b5c89fccdb4b3fbd969ebf6a1dcca8742d784c873353" },
                { "da", "1585a5bf2de3a78078481c1dda55f6b2437f30caafaa0e4a9882363a4ee666c863b3cb1542250534aa6eba16d57f609652911d125c7ab10be38ddbe4382a288d" },
                { "de", "43d39b73acc3adbcae6e68c98975eda00e178d6f960c62af641ffa1f9903397055b4aa9c6f3e43dd5c656cd415a8362a991e23b1527bea3b14493e3f83b65a81" },
                { "dsb", "b551501a8460c12c46f21a3fcd54c2a95a3aade06eaa78393beeaa4f5f8800cb809aa35fded5f453b4cf22f60fe9a4ba3b020133f3de66dd9a1216c5f4f08bf5" },
                { "el", "a5e22739e803f4c38f17c2d77c050c00c500ed51df2dc6c4837a3047750347ca983d1d4c75a5c5e1ab3b01e750b25fc2e3987308732271aa08f32b653e599342" },
                { "en-CA", "dfd398ce5411e1811ca7240763ce2ea95cf8bb131f2f4a85a5def72493313b3374606fb0cede48baae75fd4948a9d1e97edacd0bc95d2e30a4a471a58e9b3503" },
                { "en-GB", "b8284df2e8a53201a6e653bd7da9b31a18ba630293ad208c983bcca0b84cc44db272ce156363ceb1b8c445fb29b3782bf3172dcba6ec85c1d9d8086cbbb9ca4e" },
                { "en-US", "1961c5ea4e44c191b4f8959044c0df52957f9c39e5119e8087973b48589b91be100b8b02e267602c9c7d5804b807f055466087e9d3ad47204fe3384700b207cf" },
                { "eo", "9d70f1f7eeb1842cd932040c46d465f596bf6500aef9717339d87ca71ad6f31d9072b43a30ac551f195795301ef61e7a9e7137282f331651c822b5c420de6176" },
                { "es-AR", "b2f81ad47abdaf4ccb9fca109f9d2685a47bda3198fe36dc7f4451d1eaa79b47a7e5371a08f7dac46deab1beff8a3ab014d2e9fb60cc7c0e9a068fa9f8c43ee2" },
                { "es-CL", "d0edeca389b0d0eaf625290977cdc7dffa8a0607db330ae546b3721ab0089f5fe992afa0c9d461fdf5c23b2570f4786e8261ed4993fa207c341ca75c114afc10" },
                { "es-ES", "73b567c41d84f8f2ca0a09898854b5189aeba1bc0af69fbda540b38db861faea524804c9e3bffbcd62179ebc9915bd425b4258e986569c05394a56eae02e5495" },
                { "es-MX", "070e4fb882117055b48c2e9b42bd673fcf702c9ec7cdbe29fe4e53c740045abad2d41f21a1a706c36268bb45cd9fa86147cae4cde01be5528b3c2a6494fd5e4a" },
                { "et", "0110fa473b146d207859b76dc44daf010e502b6c2f7726654dbca195ad0d8271162752ada9bfe857952da923f36ca820610d95ff0bad8c0ff6ded3040b1586e7" },
                { "eu", "45759078a27c27760a17d5474c5cbeef05e76b3750a9cd540b57e8fc87c1cdeb90673320ecdf80776eba6a7637fa183113c837a2416d706d49a0c37c274640d8" },
                { "fa", "7018bce105db384c6a63eabbeb8d1b4b01672662df38a58dd546a1d4ac1a0bce92bfa2eca853384ac719f5c5150a9f3fe0256f4bc681feada709cfd90067c6ba" },
                { "ff", "fd35e0887372ea305fd28836684e3727288c17f80c5ef6e0def54c60de931a512934d7dd82a98c397469141088e570ead965e2d0c06eefb9ce56367ab39d2b4d" },
                { "fi", "bbe8b265f9c54fa936181ef1138b48d48785126d7becd11698171262270246f3383d473e7ca8e3b5f05f1b7be9f85ca20b740ca8bbd2d6b13761efd2bba941b1" },
                { "fr", "a9ee9d92bce848b29b2e571e21599e07dd37993d1c4f8d130f2177630379f134c23326bd8b34be5c207526efbcb1e6b93a11120638429b20d8c1b41a9a1a56aa" },
                { "fur", "b83308e6f2b571b68ab710e480d61ad96061e213aa12c44cf00da6607a496aaecdad401c61d79796c00320fda7513ac1c027b64c803f8b9aca8dc8ea2b781801" },
                { "fy-NL", "d5a68925735d53b5a65756338121d877bda45fa358fd1a3dda136b5096f54d718f84b53ba1781f2f9612ba697af9a4b5fc1d41711af7c5e815e6ef4c5a248f66" },
                { "ga-IE", "df634aaa22835d0e510dcb534bc2d27b7441611e82ca61399f6346fa34466ba462ee4974f1115c753784521265cb48701ad9830215d2e78a6bc11ab41064f39e" },
                { "gd", "2493f957e6ab8dba4adf3864843b6b93433fba0eb10ba31ee52f1b6814446b12a8b5be66474539094273996d34cacc88a223107b15a53e856ba5b9a11d49452a" },
                { "gl", "5bf79d8663ff4a63d0a65611840252699ca2200518faf2db02fd36f6b1040409aadf99db63b42ba08b687523568660610ee3bde326a31b97955da157bb93cdab" },
                { "gn", "25674ee39a8430a7a49b754e6542fa522669cafd13479e5f7a44cb95e877a982f48869b644dac3643694987cf60e0590e471a67df944a6a38b1a8981d56f97f8" },
                { "gu-IN", "86b9101c3db00348c1fa6da94785ec11fbd69fe488b106a151b919b7763df0435f7380a3192cc7f338cf87b695ce4d8b47e4c6331afbb12f3a580de4d1cbb021" },
                { "he", "80574a9d455aa0809caa20714b72bfbd1ce99dddf52770d2013acc2eb9c7343e87826d5490504a0580f4f1041affab55f40c65af9350d515f0fb9461bb2799bb" },
                { "hi-IN", "a133cd7533e3247bb731edc2be4e421251bea17ae5ad7807563724dbc56c13e5de9b2c1ef91e694a25f60e4c096dcadfd95af68738dabbac96a6b52b36b18e7a" },
                { "hr", "e90e1d196ef8fbf2735726d8f086c2ce62a46d63a8ef747ba7472ebd44ffafb6fcfc0f2f9ad269067611e9b32dc26c84b22c307d3e71878a388b310f8879ceea" },
                { "hsb", "7ab80a3c985a7e5b70b0e317bf36df52bddb1d0a8b996844fe0865d894508c0d2abe9d124e48b1132ca038520a32e278ccf283eccc68eb43a3f81b607d18d000" },
                { "hu", "c88925c41153c7e871e06f14379624eedc8ce543403185af5d51063e40823a48bae7c5d1e07b012960e1cc1cc7129741bceb7819708821517cedac3c07571f78" },
                { "hy-AM", "f32e2c3aaac306c875879cdd967b9ff896f5b3c5216123f28c5210fb0f26a0bd1e4e100f8a82c6cc1627e3f029499d88abbee84b946840bd02b2edbc673f01d7" },
                { "ia", "3469e6a94ff000ba7f89e71f380d63ebcc976629b58ae9beaa597a49f825d79aca732b7af406d9259d508de2403c799ae1d9661b37a12cf94d1b611d99e42b32" },
                { "id", "1b8967d59a23a3fde87a16e424cf29a109a3490835441c286ba97491975a17150252c9d6585d652c01fb8f6ec09cca0f8e91bcbea8e6fb67721e90b7907c01d4" },
                { "is", "6039dac77807c51ab4faf0e1b549bfcac238a3525c3c7ff351aa11d7fd90bb35162f6c33de253a73b2ecd3e0892a3bca7e41ecb279b094129bf5d383d237b185" },
                { "it", "f0ef789900afe2f323882193d9eaef4c64f383d98a5622d936c0f77c0097f773bf06460b590d44ef8d35da45f909ab190269dda623003d6c62405a7b018ad4bf" },
                { "ja", "8e185eaf86ca3e207e68e578f2ac689f48ef73d668729753e0541d34a70d2b02ebce18a5d954aae08d0bfa3e46d26cf6898623ad2c31f7d9331297227cf654cb" },
                { "ka", "d940b98a652e38983b4b88940c8d9d3322b165e3221a7fef28fa0e91be61589562424e70954c699327bc944461f7ede09281cbb21b9a10bf748966168c92a47c" },
                { "kab", "4bca8aa70c73b713b1a5069ca90e73aa509d411ee627435f10d4445daecfc356fbac2ca7669c4354fc9cbeddfd8ad7074771fbf88cd5e2fc7623dab55d80ad5b" },
                { "kk", "ec7eceef83a6643d620ab9a1f2aee65cd87c1a2cd0ca862c395839fb548b73d075e3a76810b68749990359bbfee79ad6ad30ec97103bfe02f1807b21c0cc922e" },
                { "km", "4df38317ebd22539fb28b70192c390547e4e3541aa7652ba8d5178125190b1b6063417b260aeac2ce474537d13fbea786b7c6d53485c6660b13a0dda87bea767" },
                { "kn", "9c3f28987dc6cd81ffc2ba53fbb9f368a0cf0485bbd757183827aeb666b2caf84255bbbdb78c4f793ca40c8731510512cf4ea0e18bc7b41c1d5c6ab4796610de" },
                { "ko", "eefa4b027aa3879ccc08d3fa3c4341f1175e39d2176e56c1062dfee4a76a4c88b4e774a3b4270b054e70d32a4456a8c6a0930f55b775edeadc0093c26a40b7b0" },
                { "lij", "234a253f033620c27edf267b674c8476ce7f48e904ca52580031f519cffc6127ff3aac4f16ba5585b1c110421bfced110e5a18e4a29d24ba1a738cbb71cc9920" },
                { "lt", "f914ec6c302cb45fa690182f8eee6fdf0517b3558ad23ca2ed03e4d5ad8e9e0d73a275d47f7bc603047e9c119c56e6e320a26e0f6965f248f251cc9868692bac" },
                { "lv", "59bbe99450b02d14f7779d1f90b7b058e6640abad1530b08e8fcb1d1783d9cb4afee0e7fa7e64f7ac99ee55cfd87a7e7541b3bb81ad662fe4f655e189e4f403e" },
                { "mk", "44bbb015009988fadd33d350a422da32d18618e598f2483e8739d2fdd308b81a64fa17c6d05d75b0555c9e354be2b52c47a65e5f4576533a98f908881d5c3849" },
                { "mr", "e290e9a5da78d357897f77af60bc581bad5399725207550e5b043d5b3196326bd9b991c3a17fa3493df52d4500c851b8b6d92572f7e1159e35a80c20e30d35a7" },
                { "ms", "c09e7176de8818bf83e76095af8847b7428867681e08956eb536495f3ab6d68292a49d342e8c69d53b31a1b9fe7f69b5c9a55044834d9ed7dcd79cb164057c73" },
                { "my", "ffb61a539cd80e4ad93edaf1debc56346319ee3917260ce48c6490b58e50290fbf5be5ec5e77b8273f15fe5be16c597c28ab881393e6177bc9d27221015903d5" },
                { "nb-NO", "1c5bc02a24319160790dc241d2f87691f93ccf1ec8100e279eb546029296a2370ca5e55fad000a758381a153c0714214ce6f014ac316dc92a869f06db8c0b822" },
                { "ne-NP", "6b365003dc2fbc00255085ae243fbe78cbc7c5beb328c0672d8a8920aa480d2582dda30b6a3845bcb959c8fb1ba3fcee5a812609ca1d46b33f29d00d66219481" },
                { "nl", "0484a8f00e2cfae44f61877f544b517c712215932295c739cc49d116ee5d2d9d4f25e00fa5ea7e1892bccaaad86feb6641ee524c6b1fc8c1c25b9e2b83227c23" },
                { "nn-NO", "e0e4a8a0193a6ea1f4bdb25f6b5b5cd6bb7a895d46a21be2b8b3ac8139f04842ca3b00ebf9176aa08b6e5eb707fbf76363a2e19bf74cea48095bd95504eb5f15" },
                { "oc", "b581594250ddbb6888f1992ffb93e993ce197e0f1937214d12bba004230197f120d6caca61479fe9047213e3ba5b95db0afc5d643bee849dd262f3f84aeb827a" },
                { "pa-IN", "ca996248a8b0deb2be36ab6fcbf9290507c5b71fd1f29ef85eca7350a37c6d34ba6b6ec135d1d01a7263f29a1436941e5d3ed0070ccb76f817a758ae325d107a" },
                { "pl", "5f6dc13f07e3d216e87eee5a081fa42f097bb42832f2c713c38f65b14b78ff98147cd9a4210daa90c1320382ac654116e3612be4b83ddcbe74643c41d3effc91" },
                { "pt-BR", "4d321c393b5b64b89c86bc5ad787966fe06bc308c6e898324beabbdab30bf9983a190e74f5954506ff8c9b6ff61142e91271d93a0f1b33d097d3e58275482c29" },
                { "pt-PT", "cb441e8cfd1d80a14d608a339fcd998310c9cce4429e4571503d614616e347407f960102057c1056bcdee89a71e096bd31f4870d755677b0f0a6bccd74ac1a90" },
                { "rm", "261b08c464fb8991665989da184e106e1e1496b0fdfbd93b9bb54f47432ea33fef29894e25a87377a743666cd5074a5dd7342d74f353c83777bbdfa867402ba4" },
                { "ro", "71378fcdd7654b8384492b7d969d23bd00da9a1de12570bf1c99c2f4b48078af73125e95ee63aabba49190e582285af6480bd342460138fc3577d20b73d91164" },
                { "ru", "228cf860cbb867aadb251a97df89d06f7b18185c78bc9e2c6394f2c7ed6204c37ab30167247735f319bf2035cb479cd2fff6bf8cd877f7eb4ce4523ccfb0dcf6" },
                { "sat", "f2fc218bfb3cac53a6619d16696f67e06d365b1d2a49994260fea8e402ea5e578f53ea01a44bfb0dcee916bc0f053a9a8195fef0df7c19d62ce68e898099a87b" },
                { "sc", "bafb243b92bce5b1b94b07ccdc3df9f67601d4bd53d6176f5bab4c12171d282396c679fffe723c0eb10924f8c92d061e41c224730b70e88c7cfe3b4086660241" },
                { "sco", "5d88276bba33146ba3e860254084dcc3e0089362ea50e9cdb9febca1da0bcd889ac72390731b1b16e537d57e81677644fd26878c17818dadf27e522217e9ddfa" },
                { "si", "0a683041fadf9efa2ad80824fc4eff4695b2b36050cf821f4cf06b1f9e3e9066856d76a4295a63dd65d7bc185c4ed352401c1cd9d7f274cf70d3c6bc0595d5d3" },
                { "sk", "49f36f79d5430194ebb63112d03de28bcada43af5dac41f02c3389e1ca635796a3d34851a8a218c165888c60b8a154245f6c14bd2408ddee8d0c3d69b5df98d5" },
                { "skr", "ecb1f48b779d26a9b0b8069c7669d4f8a8f3f926b14d3bed8e05f70905d0233349d920fafa2686b87b4acea21a8fbdd1cf7705b05f055e80262de213d9767f3e" },
                { "sl", "b75c35d8073822763f89db34d2d8a3fb0a71bd95f34a250853c5923fd68d6f8c743b44cc103a2e80ae52110f7927d8e6dd5b3fd997317d871cb1ac0ff789b1d2" },
                { "son", "5c88990ce917f22bd5996e3a6f1ba7eedc55ce3831496e0524dc41f0e7e00b2a9b59df1c8e80ce6cfac10d1985ee83c5bfdb5e8290acc1fe451f148e64908599" },
                { "sq", "6fcc766c8d36c47c1b3e494681a04369e78c0a53bed27ff2060059b1dd4b17068c39ce35b52533ca93c07f559cb6fcd6f8cf8c3eaef005ecae7b09a87bdaaa3a" },
                { "sr", "73754e72cb30782188560e8d095ade5a9f7da4a88aa3f7542230b7ddce5a7e86cfb9cd03befdbc81c09bf5aea320b2b60bc4aa7f61faecc690689cc7e58f557d" },
                { "sv-SE", "5038c9ae1650ae944e3a86b43646fbfec8fc6ff2d965a99c290aec836fe22be101d648052eb7cb93ada5584a68ab3b008dccc926a14baf32ec42656504b6b0e6" },
                { "szl", "eff3896067aca326da718d30fa2c0201fc9794d157db44ee26d32762960914a9d37db8643a190292bb41b068283db2dc72e6cabef3f9f517824533f65124ae7d" },
                { "ta", "b2d07ac55afcf7a38d0f3e49f193b45f4686a24b50c63c41c13828c53a15e168573246e5c043406eedc75241b2b97bc703b9ef9120458391d1a6d8cadc9b7898" },
                { "te", "bec3f08e18fe1af7c7e0e08ae4ae19f79db016dce417dfe3e9a3b03d4d9938843a36c6760b42452ddb52a99a15cbb251910a8ef13903b234eab33709a2ae1672" },
                { "tg", "d8ffe1c7bb93e71570ef0c90dd272f6dce4bd0fe986afcfd447f037c362ed5f97e218aaafa2668745919f1c1e46d1dab8507122a859d3bc91ad0183267f25b30" },
                { "th", "c1508c5f9c6faa78e116bf694931b89170701f70ed6eb8ae614ba8ea24332396df1135173618eabde28da58bc2d3b294091594c10069fc53ddea5768e8d63161" },
                { "tl", "cbe71942dca10f4a631772314eb8511b6bb4439be2e37e9e8c0a958314b8f8a0f4e45a8d79402522c18c1ae9a3d65eeab2ee56b0e089a99f44476f436309b157" },
                { "tr", "775d682b7a6c5b3d7a0bac9601b002b31441665cad336b6f5f1c2c0c1c9042234afb264d35865e47472bba0c44402bddf9039014095dc38a8e116466c9079cca" },
                { "trs", "d87627a4e48f8b7344ac99c7a14d4b474f4c9fdf71ada2a8e2d41efb350857a29de202399f58de56e979fa034aa22083186547315b57ba23c943065f02dea9de" },
                { "uk", "a9df6d4cd1a727784963eae34fce6791a840f932f19d3c12fd88212919a91d969927c3548cb6ca051c4f436c26c099e594956d7cdf95ce5a2a335d53154425fc" },
                { "ur", "254979b9247a2dfaab6dd53a464f4baba217026bb70a7be81885e8aacb20406705b62c785b4d20b0095de4775218bff0ad8af46f49520123e522c94f3878312e" },
                { "uz", "8baab63724d5456bdeb6c8d170a0288cf12874c15e44ab2b82854325791aa01a8271b21255631e1b1e867ab44fa32a258ca7e17bcfb31d1d23ab3ca9be7c6fba" },
                { "vi", "4481c895151a86d47b073e80229a4217f56b9dd10ac97c1a7271a067680ec19d61336016fe2ff960c0bf680f0cd4249201d6616bf1639d904a4f7b7e28185a66" },
                { "xh", "79798428f570f3c39d78d7fbe1c24bd4b603423dbb3178cc26a46e10b5412beeb20a24780845e9f1af9ac69a4210217947126926e56349722a08395836e88f68" },
                { "zh-CN", "6a4cf3141d549484e381fe7640c458577f2c920f6564e55936e8025da5edaeaae3368900f8b6529bdc5e6f7853946d55b0f16aabe4bb53b8466e34f6b777d514" },
                { "zh-TW", "d51846555f5cc38a1330df98092cfd6f8d4cef5daeba2d68183d752af7fc0ee633a2eb8eaffa54f3148ca0e42971dc402efbc39f4f6e620dfec36f6c403ec858" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/142.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "12c452b4002263a2a7f56a6933b64112280357896db48fa7c14664f4fa92cc497c42343aa6d803cac892a909f6a2e761fe71208cb52d09412e094c488dcc2b5b" },
                { "af", "2e2c31a607a2f85184a30f43dd91bf3de82d18255594f0cf50f5c6e146ff231feeebbfa65c2f3bc82cdfff586eb15dcc4a63a6e6ce2409aed47eea204715cc2d" },
                { "an", "3c438e31dbf7c5cc2d9eb5ffdc1634ea981fe7bbaa4b3a09b4bd0741c57c4ae055c848cca36c77c353c4a98cb852be186120f1cf3bde050c747b3bd8fd7e7cbb" },
                { "ar", "5d67099d03456544dd92ec15a555b3e925acb778cf2bf4e0557f783cc493a669ac6b3c998f7a5701281f05d8596c4790bd5f84d621b366dee7624c7eeaad6f79" },
                { "ast", "44f4eaed655cbe8d44a69addc78fd7774e76926d779500a402e40828865a88549dec35857e7c4554bbacc6f3bbbe36bb82254d80826b9802fe1264cce603f647" },
                { "az", "dcec6b2f520d639171e5060ea6d64507834cf043917e73d435d24b625909f62ee3d5b7d6ea983767b096ba1123c6ee217130d67f0a8ff0b795ac533df36076fd" },
                { "be", "341e67122f7d5e8f21bd0d381fea4be3103ca00610dfd49060d3b17d61efaed4a5103c6fa0b34bf56ee3ad555722316f83cef14376647cdd47ee5c7559d84d46" },
                { "bg", "309e78d24fe93c6a3b02ae03a20cc6e3be446977dd4a333d07a5865db7174ef7ae575715d9d3dbe542d4844496879059223cfe3c4756b05a113fe218cf9e4788" },
                { "bn", "cc050caf54b2020f9b250d764c9ce554bd6152f29e1d96549bddfe4da2be4a300fb15e33c6a7cd44a5eb411fa28d240448042248a73a156214db6258b9713016" },
                { "br", "9ad492affa9a44f8e26e8388b988cb49c6de713f489ea5d405efea0d16ba637c83c1c56c9f57a98153c1fee0edb0cd4502e383ce0d6f2ce727324c2e4dd4ec89" },
                { "bs", "c6c3590e6365803ac23d5392bde46a27007e2f7524e06e3e1aea296465df97b852062f6fe10b25b209784eae65324d108c83aada08d6d338de6513e55d516a54" },
                { "ca", "2ffe48aa3aa83ec096c39effc1754affef2d1c58f3f2cc9c9d85b752a5898f9bee517ab3a609d3463efe435894031c0236074f67fb74f282f7bbba9a3d50fb19" },
                { "cak", "12de25eba58c4df650cfcd257091fc143a218672f7edee8e4fae1b35836200017b2a2699d79c9ffef67c87b31f8f14f15e62ae49bb061ea69cb947f85563b726" },
                { "cs", "a675f5ee7bc2cbff43b6f7e439611a5dbfe3d955819cd04fd92423bd0d806f980b9ba92b621caa02cc4c419459fa970b0bdb6f822f3b74473a06333afefe146e" },
                { "cy", "5796bebd9cab6531a53feae37dbd93321ac2d50ae2a20ee0258e8361009d5cfc79516f362def23a8527dc9cfc9be862f51c1ea830f1989a01bacfc02aab61550" },
                { "da", "754c91c7905dc285dc178207d9214b4a3d8f35ba0f786fb520fe3b59c0c761bce3c3771ca6d964f2c671c3c0e8f7a68ad14abc22952235927924ce16060eb321" },
                { "de", "1f3024da455495e69b5e819d830a3dcabd939aae10d445a015aa4b820d25c6650498d55447d3150571df950b8a42bbb1d1df34760305ac8a4714ad58f780b3f7" },
                { "dsb", "68b057e348d37af9f982a973e461e328485e760906e0c43ee4669a2a4d6668ca917839c222d3c890d7fcbcf763b4b2c79ff51459a9274ec60132a96770491cef" },
                { "el", "5b668e7b1d7f6de0a40c167b7471f05d810c92a01c64361a592ce7708ea540ba8eaa244da6ec05938cd82b238e1861ba03718984147687cfe74b6ab5f36061d4" },
                { "en-CA", "db4e2bb64377edd52a2c7c0b0812731fcca0839d9f8559c81e7299cc072222b6550cb5d68fe1edb3ad29839850f0e4e4a62cf58a862bde36c574cafe1c68fe29" },
                { "en-GB", "9d91160b60612c2501feed0d8627484db491463f58e9fd4a34d24e5026e1a437c27522272b18b45b393baf8f8d6ce928d8ead9d68849eaa7c2c11590744adb95" },
                { "en-US", "6196b94427b3a7ff4262f15dc03f9f7977b663c48d7e63583f45c7019ed28a7e07f273f18480bbb69624d9818a0646973c63297842461b149148bf539536e607" },
                { "eo", "1b2f20f87f3098f846ad48260752263d6ee56eeefc7ec5d71dc696ad44d54ad6ed8d5119db075a784197c8304b7e16ba5d63c7fef77a6770eae9b5245ec24cbb" },
                { "es-AR", "01f634d4c40c5f0ecae207b464adac95c12bcadc3226d96f9feb0203df8fdf24a99a2a81dce7ce94c608a98b38419e17413117e6269e62fa2d1eaf9042ddddb3" },
                { "es-CL", "1fc36e3b1cd2dd80af9e72c0ec220a3003c5a96714787ad11d34ef71533ea78314b7b6ecdc1e099af839f4d1638230f921be8e037a1080c38315ec42d38972ca" },
                { "es-ES", "9a561824ffc7d16dd3faa8be9f3742e43c7cdb07757404dc2f6a3340d2a3176effbacac54579ebc375351302651097c7485f3e523dc21dd18508592a955c10b7" },
                { "es-MX", "c0f2ceabecadcba50966f879a259898dcb21ff9ffbc5ded46646b817e70ec0121edecefdb7c229f1dc87ffaa4d001f1b5c9208dd3563ddbeb2d1498c9a7401e9" },
                { "et", "721b0fc94ba5815dfbd03851b41edf517e2ec083ed566f7f18e1dd0df80854c36811fe70912c63e574240c2c4687747be0547ee67ebd04cfced1bb930042dd4b" },
                { "eu", "172ff2d60e0c9f82b49d6f80e1bc0436bb26c8f2cdb6c79c4a40ed967cf49af0243ec8ac152b8fd254a42387c1689af23eb6b7b10818add7ed9f90986af46934" },
                { "fa", "c041e9375f4715f24c9c17bfc38ebf36c9d7689b3ca32a912450d8b6a3f4b587bdcedc500dd2678ecd1bec4a92be14e241c35130022696312ee749e44f19d1fa" },
                { "ff", "218d13cf48e7e8805d243c69f77fa146173d80aed1bc453a89976e0c6971f941b7813fbb13ba33b2cbc7361b29164ea4fd8dc817c09cf578d58016a96fa52095" },
                { "fi", "7cd7f9a53bcf4615146928ef870716bbc8c98b38b18c5a64624db37a85a68e51196afe66bcc4300805c173008fecc0d54944adcc06959b2605fb4f6685c05e3c" },
                { "fr", "1b86ba7eba10c7be7e689fba725bfbbeb6bffd2068a5f460db023af4bc221a6b293ddd39160497b81b0f0e250c876dabe4f25d51482f73c04107478c39dbd46b" },
                { "fur", "1eaa5e2840784d57b3f03081faa36169e85cd09a4b792699ab60648462c843aeae2a76ac1cd9ea455595d1dc9573e9f76c2f093ae493051d27a4fb1ddbf38419" },
                { "fy-NL", "c1b5573930abf396390aa4746ffedc74682f60ba82ece54834a6b53a31505173d619299e5c7e752a5f522fbe41dffa1a304073ef91ade97f11425f126ac7dab5" },
                { "ga-IE", "1e0e0608f7ad39c1db2e091bff586351e04a3a0313741e160893fb9e78c034bc9cb4faa53ad8db0dcd088f9590c34347016e6d253a051ad00644c0ed0dcef24f" },
                { "gd", "828b991424cade87dbc0fafe9051cd1344037df7b4dc77b3bc18a49c3f746c09f29eb4e8e919b15e2fa1e8e8fd3e3ceec8522093deb9d86af08502949aa9fcc1" },
                { "gl", "c33e13afd7f08c8e4aad8b2069d3fe0fb3dd383616b5189bc5f9d5ceb077fde41bd851f3ea7c86eedaf7ef9916cd7ceae727f76de91c6526a98ebc6a561a30ab" },
                { "gn", "c291c84bfde8ac72fda94134eb64103054e756ab44b2ca05a5fc0bf6ec5babca189562da81230027595701d7fab62ea3f5d4b3dc428879d8e79ce12beb54da0c" },
                { "gu-IN", "454883cbb259c067c25db21ba522723bdbcba50d89e84799aa46d1c9fd01f2b607523e27a22e0d14ec4704dc6c9d60c64539f79ad14f150f244e4974990e3021" },
                { "he", "3981a893013ac07d281498f2ea437c25cf830c4bb35c7fe26e5e3ea00facaa910ea5b008fbbdb1212ed14b085f7938099a324a3f5bb02a894f51084fb435cf59" },
                { "hi-IN", "f5a00ef0bfbbc972b5e32bd1a384713b4373bf097d350ce6b15bd11260da2d0b3996fd69dac77dfb3bb16c2e27d14bf66b55524c18b513d2f1dfe5569cb27be3" },
                { "hr", "5c330a1bd6d72dc214287969b449ecf29ea9fac114b84e23f9328f75cdabb1df505135e91285910b06d39edd5230929389188810cb4e26e918e0fa302f4da636" },
                { "hsb", "2b16f5ca1d15127fda4879b319f4f432fe1818f940d73a3e42fca7b12483da4e53c0d5cb4f2d4aba14d36a860ecc58d760c50a679b482e119ea28093ecbb7f1a" },
                { "hu", "29bc9d8470e841733a920b4f1a4cf366abf2cad736d5490624a7659fea328b2c5de1c601331c72cc62e78a5d26e0d133621bd10678737b52d1c4324daee8ce5c" },
                { "hy-AM", "dbf96d2be271c52ddf4f4c31a8c096693ac80138e22d9045849aadb0f61681b7b2680c4010118fdff34a2fb08a3df9cc8c32a05990102ff9597c5c7130a42875" },
                { "ia", "01b5148c369aa3a11fb93676bbcfd81a710b4359f6e68f7b894252757e187645e4b763c8cdeba94ec824d655f88fb899b2a00b3edf0ef54899392e9a0bba0142" },
                { "id", "f87ec18b529a61d060d651c07b5de9afa4fdf2bbd5a6b1010e3eff345518af94f7c7002d910264f4fbbf516a4a16e63839c3bb2bf9f5fe60589d8c017a2e8f81" },
                { "is", "0d112c071dbf6d30babbd99e88e5bb71837b83a96d9b614720d102f243b77eef64505f13058510a99255f5a2e3444c17a9aa4cf802ad25d36f521a3292976fb9" },
                { "it", "41e6b9530cd94de719dda4efb7a1326b3983404b63742faf5344e5b56f70f2cf6be974820d9103b418189001fe9816ce4f23ecca995f232b16161597eb905b69" },
                { "ja", "58153e7ac3a0bc211629810617a9ae629041f037f8dc63450f8e6b2c0f84ca2c9cd10100ba4c4aa453b71e2f230685371e2a401913c65ee99c55e2d2cc93b347" },
                { "ka", "931abf9bdb41b5284515d94d6ca307b3a7a3a91341d1576eb83f3ae7be7dbee9d150830e20adddbfc1a09e1b696556d0def2f189a49c0c50dffee37c027b919d" },
                { "kab", "ea41855f662416624857b19d485b0f99d86e20de68b96fe6da754629aa2d184228724e62959aec302e6a1ef1daa0a14ab25d91258dce9bd60378128a30eba253" },
                { "kk", "a9482e57f9f7f150a47dd43e038a9fb84f2594e2c2f160ebe45e92e3769960c1119cbea650c8e3a9ae17c731da2f4a98ff752ad1e65db5b50242efc6af0cf0e5" },
                { "km", "6aae914682b9605669c48039543e03a2084f6e3fa2825b6776e2cab6b38ac4e391a2d7efbbeb9cc60586e169b4797623167fae8fd2e14d55f2809d2023a25140" },
                { "kn", "cfcb2aaec96bc9416666e2f10bd5c1c7c999e6ecacc1da45e9b7f6984cd4957b5ef78f53580317aff72725792f9f5663dac392ff4483cad0c5aabae69eff5bd8" },
                { "ko", "384d9fa5533ee8ccf2e2f707e0075cd9c3f17c954ef1486d90f3739b12e11173482f9797ed1df2788b0a4fb305f302439e43c314e0bf940787adde3c5e9e6c0b" },
                { "lij", "9cfa29ff02fa9a2b46fa99b07030ebaef5909aa69d5d07a0d9ca2a4ae115c23dd3b870f2c232509ea79a60f0422517136a82acfdd594e354310f01ff4c93bf92" },
                { "lt", "cf3050b6793bdca0ed2c3b9807bb85544b04b51a834edbeb9deaf6ce942739318065920f28e8ad85db2c4b6c1edbabb4439cbcf81e4fc1ca3b8e721d09e274b7" },
                { "lv", "de6d2495113757212afa033b40308515f7dd806bb5c0189532da207445981e060a1e7fe5303ddd87bce50326cf61beeecf5ee8e7c6e36588f20a265a5e3fbb80" },
                { "mk", "ebf8e29a69568b625aed383eb608c60b5c5cdb21fc9bccb7bc6733e5ccd9212cf22d01739298dea20b9186218a8b213b373b55b1a4812ff4b6940534ae16232c" },
                { "mr", "fd60cac5788250b5928f5fb194eeef8ce689c04a68ec71534f0c50c873163a144889f744dcb5f7da2c550bdb46ba03c7e8a47fa3ee06893f7f1c8f732338d683" },
                { "ms", "002c6097c03df847f229bd2d6f5af3c52a707c83cadce3c01ea414b9f63f2ce897f353d54467ae62cd98264cdcde508c564e84b7f829fdbce014dd5e9c4459da" },
                { "my", "bad0066859e4f716fd7a0d27d9ad19f6cdff523dc21557728c7075a0e642ca13f8af84eac6dcf386962393694c157502d0182e38bfaf661dcf8e64672029c930" },
                { "nb-NO", "d323c1036a6ea11791fe1c9e4b54c2067c8976f9317e0db806d792f0e4b1165a4ab81f8edb1a17ee90fbc8cddd598246e53473601c0631cf14f4b6db36351973" },
                { "ne-NP", "b4e581b65dcdb6ce9027ead23d5c0e81ccd3d414a7c102aa250836228ad03ad4aa0a9e6195f50443cd62dbd3b486776d35976e02ab6d456b328783917d3632e1" },
                { "nl", "20f2610807bdbc0f4f4ccbb8f04055940b5ae0d5309e2ae035b9618ed97bc090e10ac37bc252a0931afacb49e92820f969121ffa855214f6452dbe3e065b9996" },
                { "nn-NO", "774e94b52de79a66978043c8284c37c3bada0df9511c305b0684093ec1ec36c7cf296f1db01800e48bda3e9b9f3a883af50e4fc82b472c261d45b1cd3f81fbb5" },
                { "oc", "71028fb77d83ec9cf81d80089b8ebfae9af6a4e46d90e857e53cd451240c96299e1270c94dad3a06fdb6c050ccb4392f38dcf914c28208f31d5626cf251ea54b" },
                { "pa-IN", "dc3b41009b436ec64b8d220d295ccbc8be0a6f1c1b04a52bf154a296574dd269a28058b93d9015b3cfa4d6c7cc1c8469aeaef4845fcf20ca203e5b68ba09cf12" },
                { "pl", "776238efb20568b6ef0e91fb1d268d378e58b57d3fcc540470474c54657211cf13f4d8045052a10d5f838612209cfc4498c4f716648f445d8cb0580271eef737" },
                { "pt-BR", "7954ad925b58f0ff2fe5646dfd298376383fa548318b62534ddc26e37eb57d63d7ee1308a808854d938e8fa890de5fb1faed69eefc09a16deddc2094cff192f3" },
                { "pt-PT", "6a1cdcd564a4f6354b5fc3c400fa3c9b144bca0846a9552e816a3b2a60c6f7b74d1f75aed98a9ea1943e487cc4b41c3f561cd8636b0eb7379e9be55aab3a2b8f" },
                { "rm", "cbb830321dd7bdca6c0ae3cf76267d9e8772c05d49c82b60d48f1c0cb41db7a5a78e98937db812795f73246c2d67773ea08f01cf20f65a1ed5a716d4b3e4330b" },
                { "ro", "9958870c3e6e4b86c30d24b86865dd298ed5b11c811207130bad972ee1ae823403664cb7c217040a8bab7df0dc74cc40078d1ceecf2b5d7e2656b6b6c59f44b1" },
                { "ru", "ede9892a6bc9636db06403300e820fed71ea82985b30c1bd6548d43d0f8ac0f4103fbb2952200ec9595934e5e9da115e043981dcf0d6df9fc9414a6f9d4d33a0" },
                { "sat", "02fb991c0bafdf5d6d097b867fc2f9aed69e802dfdd50bd1d1e033ed8a8405f779a1560db49e08906f9821f069b29a62dd8a3b4c34febd705bcf14520a0b655d" },
                { "sc", "a25d057c8ffe7a8f98f5960b9d03e124641b49b4a7468be1f859fdd7484d12646ce28f9f3cf33e7cbde48cfe200b83eed6231cd8865a92378e64ca67710e77f0" },
                { "sco", "582dcbb0ee06eea4378e9154df96de3528055ff6f907c61a4705caa41b40c0cf291027e9b0baa3376d294a8742956ca3a797065933d9b8689869be0d5a30532d" },
                { "si", "a808733643f0fd021e9de1d5b65b34e6a08cd35e4a0c3e4c0be530a1e20107507863a5e70571b7fea768d4ef0091ff243b87e63d4952d613a8f81f856feeca47" },
                { "sk", "bf64e836d3d9b92fd19ced608fca11294e4883351d4fb0c0781382b9a345a96d8c4a2411a0a3896122c0662a2b115914cc98ea16c981a15eb4a5dcd6c3f404b0" },
                { "skr", "c19bed79b53fb89f97259a674504d0c4d57e4a4841b6293543bceec3c569d6bbc3477f15732a7de341fc5e73b7eb525bd7eaa533f8b1eee7bf7ce8a37da9469c" },
                { "sl", "35e74ff68e70a8977a6c0483406161739f38dc81f03ea025ee80cc751360b8cc6ceb2e0cfadc0cdc04f793b6d2eb2cc73405a2e6014cab56b73672dd5e7f345c" },
                { "son", "1d9ab5158e69b15c86094720f426d217bf1085f6257a7b987da3cd86a7086a5b8feea9722843894ab0b7a5aa6c0f4e3688fd5f716fa810f48584a47507bd50f0" },
                { "sq", "6102e6fe6df905da7761ddc78e94d13e1e46e4f1e842f7c1d8edd290e9df721e6dd182c68253e8a1cd58f25c2ba5612924a61e3d8e5717377159ebf1e6db1d3e" },
                { "sr", "1bfb3163f2d019ff84efdd132914c0166499bede4fddbea46b9eb336b71651c8019551d76a4846eec5bbe67ffe4febcd201d4be0d49e1426f0dfd3413675b4da" },
                { "sv-SE", "61c8ffcbaa858092060c25857293f3b5e9f18c4a7d4449d8af7b0852e6902836fab4ba6d132f18eacff762f852e8f68c3320cd98f8eeb7441a4b91507f11a476" },
                { "szl", "b4d212c00dca3ef5a795997d4cd9bdd0e840b896dbae2ebb9a09cf5981f04d957c99d75eb2dd8faaf97bf9b462ffdbc8d2b47df66f5e503b75087417d60c87f3" },
                { "ta", "5501de2d085ab02e88ecd93dcccf91ea728e69ed1506c90446ebbd9cb6ebeb7ed225d4cf7db9a5a35bcfbd2dd5f23e7b3c3eff01c569b77f0dbf21147f59d857" },
                { "te", "5930e0a293fcd820bce38ba177cd76a96c275759845dbf508acddd8008980c3dd27edb0cba8f4ab50907720fece5c79b9c99da2aa159af6a2af42fc7a06b2f1b" },
                { "tg", "be24ba6cc609699984cc52e20cf0d5d8c474454c4f364dc6fba38381de3fb3da6205f82468b0d65f6d69c8a32463155180780df6d8b2d78eca62c08d2f7f9f27" },
                { "th", "f99942863710d27234df4f77e14705ad127417c0a726b8027e3b2748053989c686b658e20d8469b892a0afef7b8875ff2c28531c03b222f8bdd74bc2ae499552" },
                { "tl", "d4f73baa68022621f081cf6ee0b2cc9cccd1bf45c2454ab3fcab662e7db30a68a638bdf8b2d24bd2172893a13ebde6c64e1732faebfd26056e9baebc05254363" },
                { "tr", "756db223bb246dcb38c450b659ca8b742ec0e8b916d7ac1a16b6fcb501b79a5d0670c238b82f081aaa5db45e2c6f55d3eb709e0b8395a6663234af9d6861b0f0" },
                { "trs", "988e0800108b658fa770e4060fb27bb37b88751e99ffc042c8563eb4b290afc9cf7a79d57c068fa7bade3e7cff3eb3b8502626e908baa156cfe19cc3f95653ee" },
                { "uk", "de5d53e979150ed8989128d46efe29d5a2fb45c8bd06eceec85904df457aceaf69887bdc157906efeea8af12f56132b16c4690e20999e90448a30b3576aa9ff7" },
                { "ur", "248aea38a19580301ce663aac5e6b120a59c7a82948c76d554271574fe520082d615d91dd7e9f4d8ec51d17ced07993cc42235c04a720edb6061f482ae90cc3f" },
                { "uz", "26810186d3b6a693e6964c1e8f2d6c1b5c76f7ce4ce1424195eb09d6a115ca0b0e2f622b6f77f77e73959434335bee90562ed40a7537870dd0552c1bbf45d15d" },
                { "vi", "bfd7e3607dc1099f7880018132eaf160514c8eb67024ca4527f08efa8f529b0038f8b6cc32bb43aa33e4080f0545655f8fe1ba1f38b9e56602baea6d7ceabaa8" },
                { "xh", "f4571ca131dbd3d495dce95a2d977306fc2142312b4fb2d04dd4c3cb52bdc94d3dd2190a9f475b2199267a8534ae50289826a4983137e16c2bf1ad6c7138bfe9" },
                { "zh-CN", "33fc1788b17cc4f9e0a06d1398a240fc2c54be020bcf258ee6f07202fb25671aabaf902230d13d0c0aa556a97920bd40f616d63175c25e8a9e7cd77a1394f694" },
                { "zh-TW", "e73a2837437cf970d68dbc149678e474825416e8fa452e8e2fabe94891fbd573fec0fa84f9dec4297e47f7f4faaa5aff87ccf9b1968d575c52c8e20aceb2b134" }
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
            const string knownVersion = "142.0.1";
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
