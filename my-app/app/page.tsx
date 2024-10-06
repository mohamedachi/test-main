import Link from 'next/link';

export default function Home() {
	return (
		<div className="h-screen flex flex-col justify-center items-center">
			<h1 className="text-7xl break-words">
Welcome superiamo		
			</h1>

			<h3 className="my-10 text-2xl font-bold">Mohamed Achi</h3>

			<Link href="/user/signup">
				<button className="bg-blue-600 px-20 py-5 rounded-full font-bold text-2xl cursor-pointer hover:opacity-80">
					Count me in
				</button>
			</Link>
		</div>
	);
}
